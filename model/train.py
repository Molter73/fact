#!/usr/bin/env -S uv run --script
#
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "pymongo==4.18.2",
#   "numpy",
#   "joblib",
#   "scikit-learn==1.9.1"
# ]
# ///
"""Fit unsupervised anomaly detectors on a benign capture, score an evaluation
capture containing injected attacks, and compare them at a fixed false-positive
budget. Attack labels are only used to measure recall, never to fit.

The benign capture is split chronologically into fit, calibrate and test slices.
Rarity tables, the scaler and the detector are built on the fit slice only; the
threshold comes from the calibrate slice at the target FPR; the test slice is
held out for the reported FPR. When the calibration slice is empty, group-aware
out-of-fold scores are used so kNN never sees a row as its own neighbour."""

import argparse
import json
from collections import defaultdict
from math import sqrt
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import GroupKFold, KFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

import capture
import detectors
import features
import fingerprint

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
BENIGN = ROOT / "dataset" / "dumps" / "benign"
EVAL = ROOT / "dataset" / "dumps" / "attacks"
MANIFEST = ROOT / "dataset" / "attacks-manifest.jsonl"

ESTIMATORS = detectors.ESTIMATORS
DEFAULT_MODELS = detectors.DEFAULT_MODELS
DEFAULT_SPLIT = "0.5,0.25,0.25"

Z_95 = 1.959963984540054


def load_rows(source, warmup=0.0, cooldown=0.0, max_duration=0.0):
    rows = features.extract(*capture.load_capture(source))
    rows.sort(key=lambda row: row["_exec_ts_ns"])
    if not rows:
        return rows
    start = rows[0]["_exec_ts_ns"]
    if max_duration:
        cutoff = start + int(max_duration * 1e9)
        kept = [row for row in rows if row["_exec_ts_ns"] < cutoff]
        print(
            f"  {source}: discard {len(rows) - len(kept)} execs after {max_duration}s"
        )
        rows = kept
    if warmup:
        cutoff = start + int(warmup * 1e9)
        kept = [row for row in rows if row["_exec_ts_ns"] >= cutoff]
        print(f"  {source}: discard {len(rows) - len(kept)} warm-up execs ({warmup}s)")
        rows = kept
    if cooldown and rows:
        end = (
            start + int(max_duration * 1e9) if max_duration else rows[-1]["_exec_ts_ns"]
        )
        cutoff = end - int(cooldown * 1e9)
        kept = [row for row in rows if row["_exec_ts_ns"] < cutoff]
        print(
            f"  {source}: discard {len(rows) - len(kept)} cooldown execs ({cooldown}s)"
        )
        rows = kept
    return rows


def read_manifest(path):
    if not path or not Path(path).is_file():
        return []
    with open(path) as fh:
        return [json.loads(line) for line in fh if line.strip()]


def parse_split(text):
    try:
        fractions = [float(part) for part in text.split(",")]
    except ValueError as exc:
        raise SystemExit(f"--split: cannot parse {text!r}") from exc
    if len(fractions) != 3:
        raise SystemExit("--split needs three comma-separated fractions: fit,cal,test")
    if any(value < 0 for value in fractions):
        raise SystemExit("--split fractions must be non-negative")
    if abs(sum(fractions) - 1.0) > 1e-6:
        raise SystemExit("--split fractions must sum to 1")
    return fractions


def split_rows(rows, fractions):
    first = int(len(rows) * fractions[0])
    second = int(len(rows) * (fractions[0] + fractions[1]))
    return rows[:first], rows[first:second], rows[second:]


def parse_holdout(text):
    sources = [part.strip() for part in text.split(",") if part.strip()]
    if len(sources) != 2:
        raise SystemExit("--holdout needs two comma-separated captures: calibrate,test")
    return sources


def prepare_benign(args):
    if args.holdout:
        calibrate_source, test_source = parse_holdout(args.holdout)
        fit_rows = load_rows(args.train, args.warmup, args.cooldown, args.max_duration)
        calibrate_rows = load_rows(
            calibrate_source, args.warmup, args.cooldown, args.max_duration
        )
        test_rows = load_rows(
            test_source, args.warmup, args.cooldown, args.max_duration
        )
        note = f"holdout {calibrate_source},{test_source}"
    else:
        fractions = parse_split(args.split or DEFAULT_SPLIT)
        rows = load_rows(args.train, args.warmup, args.cooldown, args.max_duration)
        fit_rows, calibrate_rows, test_rows = split_rows(rows, fractions)
        note = (
            f"split {fractions[0]:.2f}/{fractions[1]:.2f}/{fractions[2]:.2f} "
            f"of {args.train}"
        )
    return fit_rows, calibrate_rows, test_rows, note


def calibrate_threshold(scores, target_fpr):
    """Threshold whose calibration FPR does not exceed the target.

    Identical rows produce tied scores; taking the quantile verbatim can put
    more than the budget above it. Moving one ULP past the tie block keeps the
    target honest."""
    scores = np.asarray(scores, dtype=float)
    if len(scores) == 0:
        raise SystemExit("cannot calibrate a threshold from no rows")
    quantile = np.quantile(scores, 1 - target_fpr, method="higher")
    return float(np.nextafter(quantile, np.inf))


def attack_instances(rows, manifest):
    """One entry per tagged attack invocation, with the rows it owns.

    Keeping rounds separate lets per-technique recall count how many of the
    repeated attack runs were detected rather than only how many rows fired."""
    parents = {}
    index = defaultdict(list)
    for i, row in enumerate(rows):
        parents.setdefault(row["upid"], row["parent_upid"])
        index[row["upid"]].append(i)

    children = defaultdict(list)
    for upid, parent in parents.items():
        children[parent].append(upid)

    instances = []
    for entry in manifest:
        tag = entry["tag"]
        roots = {
            row["upid"]
            for row in rows
            if tag
            in " ".join([row["comm"], row["exe_path"], *row["args"], *row["_paths"]])
        }
        if roots:
            instances.append(
                {
                    "technique": entry["technique"],
                    "tag": tag,
                    "members": features.descendants(roots, children),
                }
            )
    return instances, index


def make_pipeline(name):
    return Pipeline(
        [
            ("scaler", StandardScaler()),
            ("model", ESTIMATORS[name]()),
        ]
    )


def fit_pipeline(name, fit_rows):
    matrix = np.asarray(features.vectorize(fit_rows), dtype=float)
    return make_pipeline(name).fit(matrix)


def score(pipeline, rows):
    matrix = np.asarray(features.vectorize(rows), dtype=float)
    return -pipeline.score_samples(matrix)


def oof_scores(name, fit_rows, fit_x):
    """Group-aware out-of-fold scores so a row is never its own neighbour.

    Used only when a chronological calibration slice is unavailable. Folds are
    grouped by session so children of one shell do not leak across folds."""
    groups = np.asarray([features.session_id(row) for row in fit_rows])
    unique = len(set(groups.tolist()))
    if unique < 2:
        folds = min(5, len(fit_x))
        if folds < 2:
            raise SystemExit("not enough rows to build out-of-fold scores")
        splitter = KFold(n_splits=folds)
        splits = splitter.split(fit_x)
    else:
        splitter = GroupKFold(n_splits=min(5, unique))
        splits = splitter.split(fit_x, groups=groups)

    scores = np.full(len(fit_x), np.nan)
    for train_index, test_index in splits:
        fold = make_pipeline(name).fit(fit_x[train_index])
        scores[test_index] = -fold.score_samples(fit_x[test_index])
    return scores


def wilson(successes, total, z=Z_95):
    """Binomial proportion and its Wilson score confidence interval.

    Used for FPR intervals because the normal approximation misbehaves for
    near-zero rates; the Wilson interval stays inside [0, 1]."""
    if total == 0:
        return 0.0, 0.0, 0.0
    p = successes / total
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    half = z * sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return p, max(0.0, center - half), min(1.0, center + half)


def operational_fpr(scores, threshold, rows):
    sessions = defaultdict(lambda: [0, 0])
    fingerprints = set()
    fired = set()
    for row, value in zip(rows, scores):
        session = features.session_id(row)
        sessions[session][0] += 1
        key = fingerprint.fingerprint(row)
        fingerprints.add(key)
        if value >= threshold:
            sessions[session][1] += 1
            fired.add(key)
    flagged = sum(1 for total, hits in sessions.values() if hits)
    return {
        "sessions": len(sessions),
        "flagged_sessions": flagged,
        "session_rate": flagged / len(sessions) if sessions else 0.0,
        "alert_keys": len(fired),
        "fingerprints": len(fingerprints),
    }


def technique_recall(instances, scores, threshold, index):
    stats = defaultdict(lambda: {"rounds": 0, "detected": 0, "rows": 0, "hits": 0})
    for instance in instances:
        entry = stats[instance["technique"]]
        entry["rounds"] += 1
        hits = 0
        for upid in instance["members"]:
            for i in index.get(upid, ()):
                entry["rows"] += 1
                if scores[i] >= threshold:
                    entry["hits"] += 1
                    hits += 1
        if hits:
            entry["detected"] += 1
    return stats


def report_attack(
    name, scores, threshold, labels, excluded, instances, index, rows, top=0
):
    benign = (np.asarray(labels) == 0) & ~np.asarray(excluded)
    attack = np.asarray(labels) == 1
    fpr = float((scores[benign] >= threshold).mean()) if benign.any() else 0.0
    hits = int((scores[attack] >= threshold).sum())
    total = int(attack.sum())
    tpr = hits / total if total else 0.0
    stats = technique_recall(instances, scores, threshold, index)
    detected = sum(entry["detected"] for entry in stats.values())
    rounds = sum(entry["rounds"] for entry in stats.values())

    print(f"\n{name}  (eval threshold {threshold:.4f})")
    print(
        f"  eval FPR {fpr:.4f}   exec TPR {tpr:.3f} ({hits}/{total})   "
        f"rounds {detected}/{rounds}   techniques "
        f"{sum(1 for entry in stats.values() if entry['detected'])}/{len(stats)}"
    )
    for technique, entry in sorted(
        stats.items(), key=lambda kv: (kv[1]["detected"] == 0, -kv[1]["detected"])
    ):
        print(
            f"    {technique:18s} {entry['detected']:2d}/{entry['rounds']:2d} rounds "
            f"{entry['hits']:3d}/{entry['rows']:3d} rows"
        )

    if top:
        print("  highest scoring eval rows:")
        for i in np.argsort(scores)[::-1][:top]:
            mark = "ATK" if labels[i] else ("---" if excluded[i] else "   ")
            row = rows[i]
            print(
                f"    {scores[i]:8.3f} {mark} {row['comm'][:16]:16s} "
                f"par={row['parent_comm'][:14]:14s} {' '.join(row['args'][:3])[:54]}"
            )
    return tpr, fpr, stats


def report_benign(name, scores, threshold, rows, top=0):
    flagged = int((scores >= threshold).sum())
    total = len(scores)
    fpr, low, high = wilson(flagged, total)
    ops = operational_fpr(scores, threshold, rows)
    print(f"\n{name}  held-out benign (threshold {threshold:.4f})")
    print(
        f"  row FPR {fpr:.4f} (95% CI {low:.4f}-{high:.4f}, {flagged}/{total})   "
        f"session FPR {ops['session_rate']:.4f} "
        f"({ops['flagged_sessions']}/{ops['sessions']})   "
        f"alert keys {ops['alert_keys']}/{ops['fingerprints']}"
    )

    if top:
        print("  highest scoring held-out benign rows:")
        for i in np.argsort(scores)[::-1][:top]:
            row = rows[i]
            print(
                f"    {scores[i]:8.3f} {row['comm'][:16]:16s} "
                f"par={row['parent_comm'][:14]:14s} {' '.join(row['args'][:3])[:54]}"
            )
    return fpr, low, high, ops


def auc(eval_x, labels, excluded):
    """Per-feature separability between injected attacks and benign eval rows.

    A feature at 0.5 adds nothing; both directions are informative."""
    attack = np.asarray(labels) == 1
    benign = (np.asarray(labels) == 0) & ~np.asarray(excluded)
    print("\nper-feature AUC (eval: attack vs benign)")
    ranked = []
    for i, feature in enumerate(features.FEATURES):
        column = eval_x[:, i]
        value = roc_auc_score(
            np.concatenate([np.ones(attack.sum()), np.zeros(benign.sum())]),
            np.concatenate([column[attack], column[benign]]),
        )
        ranked.append((max(value, 1 - value), value, feature))
    for separable, value, feature in sorted(ranked, reverse=True):
        direction = "<-" if value < 0.5 else "->"
        print(f"  {separable:5.3f} {value:5.3f} {direction} {feature}")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  split one benign capture (default):
    train.py --train benign --eval attacks --manifest attacks.jsonl

  use separate calibration and test captures:
    train.py --train benign-fit --holdout benign-cal,benign-test \\
      --eval attacks --manifest attacks.jsonl
""",
    )
    parser.add_argument(
        "--train", default=str(BENIGN), help="benign capture: dump dir or 'db'"
    )
    parser.add_argument(
        "--eval", default=str(EVAL), help="capture with attacks: dump dir or 'db'"
    )
    parser.add_argument("--manifest", default=str(MANIFEST))
    parser.add_argument("--models", default=DEFAULT_MODELS)
    parser.add_argument(
        "--warmup",
        type=float,
        default=0.0,
        help="discard this many seconds from the start of every capture",
    )
    parser.add_argument(
        "--cooldown",
        type=float,
        default=0.0,
        help="discard this many seconds from the end of benign captures",
    )
    parser.add_argument(
        "--max-duration",
        type=float,
        default=0.0,
        help="ignore rows after this many seconds from the first exec",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--split",
        help="chronological fit,calibrate,test fractions of --train "
        f"(default {DEFAULT_SPLIT})",
    )
    mode.add_argument(
        "--holdout",
        metavar="CALIBRATE,TEST",
        help="separate benign captures used for calibration and test "
        "instead of splitting --train",
    )
    parser.add_argument(
        "--fpr-target",
        type=float,
        default=0.005,
        help="target row-level FPR used to set the threshold (default 0.005)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="print the N highest scoring eval and held-out benign rows",
    )
    parser.add_argument(
        "--disguise",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="also score the eval capture with atk-* artifacts renamed to "
        "benign-looking names (robustness check against tag novelty)",
    )
    parser.add_argument(
        "--auc", action="store_true", help="print per-feature attack/benign AUC"
    )
    parser.add_argument("--save", help="write the selected model to this path")
    args = parser.parse_args()

    if args.train == args.eval:
        raise SystemExit(
            "train and eval must be different captures: training on the capture you "
            "score measures memorisation, not detection. Pass --eval explicitly."
        )
    if not 0 < args.fpr_target < 1:
        raise SystemExit("--fpr-target must be between 0 and 1")

    fit_rows, calibrate_rows, test_rows, split_note = prepare_benign(args)
    print(
        f"fit {len(fit_rows)} execs   calibrate {len(calibrate_rows)} execs   "
        f"test {len(test_rows)} execs   ({split_note})"
    )
    if len(fit_rows) < 2:
        raise SystemExit(
            "fit slice is too small; adjust --warmup, --split or --holdout"
        )

    rarity = features.build_rarity(fit_rows)
    for rows in (fit_rows, calibrate_rows, test_rows):
        features.apply_rarity(rows, rarity)

    fit_x = np.asarray(features.vectorize(fit_rows), dtype=float)

    evaluation = load_rows(args.eval, args.warmup, max_duration=args.max_duration)
    features.apply_rarity(evaluation, rarity)
    manifest = read_manifest(args.manifest)
    labels, excluded = features.label(evaluation, manifest)
    instances, index = attack_instances(evaluation, manifest)
    if not instances:
        raise SystemExit(
            f"{args.eval}: no attack tags matched {args.manifest}. The eval capture "
            "must contain the attacks, otherwise there is no ground truth to score."
        )
    eval_x = np.asarray(features.vectorize(evaluation), dtype=float)
    print(
        f"eval  {args.eval}: {len(evaluation)} execs, {sum(labels)} attack rows, "
        f"{sum(excluded)} harness rows excluded, "
        f"{len(instances)}/{len(manifest)} manifest rounds present"
    )

    if args.auc:
        auc(eval_x, labels, excluded)

    disguised_x = None
    if args.disguise:
        disguised = features.apply_rarity(features.disguise_rows(evaluation), rarity)
        disguised_x = np.asarray(features.vectorize(disguised), dtype=float)

    results = {}
    for name in args.models.split(","):
        pipeline = fit_pipeline(name, fit_rows)

        if len(calibrate_rows):
            calibrate_scores = score(pipeline, calibrate_rows)
        else:
            print(
                f"\n{name}: no calibration slice, using group-aware out-of-fold scores"
            )
            calibrate_scores = oof_scores(name, fit_rows, fit_x)
        calibrate_scores = np.asarray(calibrate_scores)
        threshold = calibrate_threshold(calibrate_scores, args.fpr_target)
        calibrate_fpr, cal_low, cal_high = wilson(
            int((calibrate_scores >= threshold).sum()), len(calibrate_scores)
        )

        eval_scores = score(pipeline, evaluation)

        disguised_tpr = None
        if disguised_x is not None:
            disguised_scores = -pipeline.score_samples(disguised_x)
            disguised_tpr, _, _ = report_attack(
                f"{name} [disguised]",
                disguised_scores,
                threshold,
                labels,
                excluded,
                instances,
                index,
                evaluation,
            )

        tpr, _, _ = report_attack(
            name,
            eval_scores,
            threshold,
            labels,
            excluded,
            instances,
            index,
            evaluation,
            args.top,
        )

        if len(test_rows):
            test_fpr, low, high, ops = report_benign(
                name, score(pipeline, test_rows), threshold, test_rows, args.top
            )
        else:
            test_fpr = low = high = None
            ops = None
            print(
                f"\n{name}  held-out benign\n  no test slice; "
                f"calibrate row FPR {calibrate_fpr:.4f} "
                f"(95% CI {cal_low:.4f}-{cal_high:.4f})"
            )

        results[name] = {
            "tpr": tpr,
            "disguised_tpr": disguised_tpr,
            "calibrate_fpr": calibrate_fpr,
            "test_fpr": test_fpr,
            "test_ci": (low, high),
            "operational": ops,
            "pipeline": pipeline,
            "threshold": threshold,
        }

    print(
        f"\n{'model':14s} {'TPR':>6s} {'dTPR':>6s} "
        f"{'cal FPR':>8s} {'test FPR':>8s} {'95% CI':>17s} {'session':>8s}"
    )
    for name, result in results.items():
        disguised = (
            f"{result['disguised_tpr']:6.3f}"
            if result["disguised_tpr"] is not None
            else f"{'-':>6s}"
        )
        if result["test_fpr"] is None:
            test_text = f"{'-':>8s} {'-':>17s}"
            session_text = f"{'-':>8s}"
        else:
            low, high = result["test_ci"]
            test_text = f"{result['test_fpr']:8.4f} {low:8.4f}-{high:<8.4f}"
            session_text = f"{result['operational']['session_rate']:8.4f}"
        print(
            f"{name:14s} {result['tpr']:6.3f} {disguised} "
            f"{result['calibrate_fpr']:8.4f} {test_text} {session_text}"
        )

    if args.save:
        best = max(
            results,
            key=lambda key: (
                results[key]["tpr"],
                results[key]["disguised_tpr"] or 0.0,
            ),
        )
        result = results[best]
        joblib.dump(
            {
                "model": best,
                "pipeline": result["pipeline"],
                "threshold": result["threshold"],
                "rarity": rarity,
                "features": features.FEATURES,
            },
            args.save,
        )
        print(
            f"\nsaved {best} to {args.save} "
            f"(threshold {result['threshold']:.4f}, selected by TPR at the FPR budget)"
        )


if __name__ == "__main__":
    main()
