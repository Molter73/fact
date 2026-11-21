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

A random fraction of the benign capture is held out for calibration; rarity
tables, the scaler and the detector are built on the remaining rows. The
threshold comes from the calibration slice at the target FPR."""

import argparse
import json
from collections import defaultdict
from math import sqrt
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import f1_score, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

import capture
import detectors
import features

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
BENIGN = ROOT / "dataset" / "dumps" / "benign"
EVAL = ROOT / "dataset" / "dumps" / "attacks"
MANIFEST = ROOT / "dataset" / "attacks-manifest.jsonl"

ESTIMATORS = detectors.ESTIMATORS
DEFAULT_MODELS = detectors.DEFAULT_MODELS
CALIBRATION_SEED = 0

Z_95 = 1.959963984540054


def load_rows(source):
    rows = features.extract(*capture.load_capture(source))
    rows.sort(key=lambda row: row["_exec_ts_ns"])
    return rows


def read_manifest(path):
    if not path or not Path(path).is_file():
        return []
    with open(path) as fh:
        return [json.loads(line) for line in fh if line.strip()]


def split_calibration(rows, fraction):
    count = int(len(rows) * fraction)
    rng = np.random.default_rng(CALIBRATION_SEED)
    picked = set(rng.permutation(len(rows))[:count].tolist())
    fit_rows = [row for i, row in enumerate(rows) if i not in picked]
    calibrate_rows = [row for i, row in enumerate(rows) if i in picked]
    return fit_rows, calibrate_rows


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
    scores = np.asarray(scores)
    labels = np.asarray(labels)
    excluded = np.asarray(excluded)
    benign = (labels == 0) & ~excluded
    attack = labels == 1
    kept = ~excluded
    f1 = float(f1_score(labels[kept], scores[kept] >= threshold, zero_division=0))
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
        f"F1 {f1:.3f}   rounds {detected}/{rounds}   techniques "
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
    return tpr, fpr, stats, f1


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
  train the default capture:
    train.py --train benign --eval attacks --manifest attacks.jsonl

  use a smaller calibration slice on a large capture:
    train.py --train benign-60 --calibrate 0.1
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
        "--calibrate",
        type=float,
        default=0.10,
        help="fraction of benign rows randomly held out for calibration (default 0.10)",
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
        help="print the N highest scoring eval rows",
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
    if not 0 < args.calibrate < 1:
        raise SystemExit("--calibrate must be between 0 and 1")

    fit_rows, calibrate_rows = split_calibration(load_rows(args.train), args.calibrate)
    print(
        f"fit {len(fit_rows)} execs   calibrate {len(calibrate_rows)} execs "
        f"({args.calibrate:.0%} of {args.train})"
    )
    if len(fit_rows) < 2:
        raise SystemExit(
            "fit slice is too small; lower --calibrate or use a bigger capture"
        )
    if not calibrate_rows:
        raise SystemExit("calibration slice is empty; raise --calibrate")
    expected = len(calibrate_rows) * args.fpr_target
    if expected < 10:
        print(
            f"warning: only {len(calibrate_rows)} calibration rows for an FPR target "
            f"of {args.fpr_target}; expect ~{expected:.1f} flagged rows, so the "
            f"threshold may be noisy. Raise --calibrate or use a larger capture."
        )

    rarity = features.build_rarity(fit_rows)
    for rows in (fit_rows, calibrate_rows):
        features.apply_rarity(rows, rarity)

    evaluation = load_rows(args.eval)
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

        calibrate_scores = np.asarray(score(pipeline, calibrate_rows))
        threshold = calibrate_threshold(calibrate_scores, args.fpr_target)
        calibrate_fpr, cal_low, cal_high = wilson(
            int((calibrate_scores >= threshold).sum()), len(calibrate_scores)
        )

        eval_scores = score(pipeline, evaluation)

        disguised_tpr = None
        if disguised_x is not None:
            disguised_scores = -pipeline.score_samples(disguised_x)
            disguised_tpr, _, _, _ = report_attack(
                f"{name} [disguised]",
                disguised_scores,
                threshold,
                labels,
                excluded,
                instances,
                index,
                evaluation,
            )

        tpr, _, _, eval_f1 = report_attack(
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

        results[name] = {
            "tpr": tpr,
            "f1": eval_f1,
            "disguised_tpr": disguised_tpr,
            "calibrate_fpr": calibrate_fpr,
            "calibrate_ci": (cal_low, cal_high),
            "pipeline": pipeline,
            "threshold": threshold,
        }

    print(
        f"\n{'model':14s} {'TPR':>6s} {'F1':>6s} {'dTPR':>6s} "
        f"{'cal FPR':>8s} {'95% CI':>17s}"
    )
    for name, result in results.items():
        disguised = (
            f"{result['disguised_tpr']:6.3f}"
            if result["disguised_tpr"] is not None
            else f"{'-':>6s}"
        )
        low, high = result["calibrate_ci"]
        print(
            f"{name:14s} {result['tpr']:6.3f} {result['f1']:6.3f} {disguised} "
            f"{result['calibrate_fpr']:8.4f} {low:8.4f}-{high:<8.4f}"
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
