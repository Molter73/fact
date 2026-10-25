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
budget. Attack labels are only used to measure recall, never to fit."""

import argparse
import json
from pathlib import Path

import capture
import detectors
import features
import joblib
import numpy as np
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
BENIGN = ROOT / "dataset" / "dumps" / "benign"
EVAL = ROOT / "dataset" / "dumps" / "attacks"
MANIFEST = ROOT / "dataset" / "attacks-manifest.jsonl"

ESTIMATORS = detectors.ESTIMATORS
DEFAULT_MODELS = detectors.DEFAULT_MODELS


def load_rows(source):
    return features.extract(*capture.load_capture(source))


def read_manifest(path):
    if not path or not Path(path).is_file():
        return []
    with open(path) as fh:
        return [json.loads(line) for line in fh if line.strip()]


def attack_subtrees(rows, manifest):
    parents = {}
    for row in rows:
        parents.setdefault(row["upid"], row["parent_upid"])
    children = {}
    for upid, parent in parents.items():
        children.setdefault(parent, []).append(upid)

    index = {}
    for i, row in enumerate(rows):
        index.setdefault(row["upid"], []).append(i)

    subtrees = {}
    for entry in manifest:
        tag = entry["tag"]
        roots = {
            row["upid"]
            for row in rows
            if tag
            in " ".join([row["comm"], row["exe_path"], *row["args"], *row["_paths"]])
        }
        if roots:
            subtrees[entry["technique"]] = features.descendants(roots, children)
    return subtrees, index


def fit_score(name, train_x, eval_x):
    scaler = StandardScaler().fit(train_x)
    estimator = ESTIMATORS[name]()
    estimator.fit(scaler.transform(train_x))
    return (
        -estimator.score_samples(scaler.transform(train_x)),
        -estimator.score_samples(scaler.transform(eval_x)),
        estimator,
        scaler,
    )


def auc(eval_x, labels, excluded):
    """Per-feature separability between injected attacks and benign eval rows.

    A feature at 0.5 adds nothing; both directions are informative."""
    attack = np.asarray(labels) == 1
    benign = (np.asarray(labels) == 0) & ~np.asarray(excluded)
    print("\nper-feature AUC (eval: attack vs benign)")
    ranked = []
    for i, feature in enumerate(features.FEATURES):
        column = eval_x[:, i]
        score = roc_auc_score(
            np.concatenate([np.ones(attack.sum()), np.zeros(benign.sum())]),
            np.concatenate([column[attack], column[benign]]),
        )
        ranked.append((max(score, 1 - score), score, feature))
    for separable, score, feature in sorted(ranked, reverse=True):
        direction = "<-" if score < 0.5 else "->"
        print(f"  {separable:5.3f} {score:5.3f} {direction} {feature}")


def report(name, scores, threshold, labels, excluded, subtrees, index, rows, top=0):
    benign = (np.asarray(labels) == 0) & ~np.asarray(excluded)
    attack = np.asarray(labels) == 1
    fpr = float((scores[benign] >= threshold).mean()) if benign.any() else 0.0
    hits = int((scores[attack] >= threshold).sum())
    total = int(attack.sum())
    tpr = hits / total if total else 0.0

    detected = {}
    for technique, members in subtrees.items():
        flagged = sum(
            1 for upid in members for i in index.get(upid, ()) if scores[i] >= threshold
        )
        detected[technique] = flagged

    print(f"\n{name}  (threshold {threshold:.4f})")
    print(
        f"  FPR {fpr:.4f}   exec TPR {tpr:.3f} ({hits}/{total})   "
        f"techniques {sum(1 for v in detected.values() if v)}/{len(detected)}"
    )
    for technique, flagged in sorted(
        detected.items(), key=lambda kv: (kv[1] == 0, -kv[1])
    ):
        print(f"    {technique:18s} {flagged:2d} rows flagged")

    if top:
        print("  highest scoring rows:")
        for i in np.argsort(scores)[::-1][:top]:
            mark = "ATK" if labels[i] else ("---" if excluded[i] else "   ")
            row = rows[i]
            print(
                f"    {scores[i]:8.3f} {mark} {row['comm'][:16]:16s} "
                f"par={row['parent_comm'][:14]:14s} {' '.join(row['args'][:3])[:54]}"
            )
    return tpr, fpr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--train", default=str(BENIGN), help="benign capture: dump dir or 'db'"
    )
    parser.add_argument(
        "--eval", default=str(EVAL), help="capture with attacks: dump dir or 'db'"
    )
    parser.add_argument("--manifest", default=str(MANIFEST))
    parser.add_argument("--models", default=DEFAULT_MODELS)
    parser.add_argument(
        "--fpr",
        type=float,
        default=0.005,
        help="benign quantile used as the threshold (default 0.005)",
    )
    parser.add_argument(
        "--top", type=int, default=0, help="print the N highest scoring rows"
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
    parser.add_argument("--save", help="write the best model to this path")
    args = parser.parse_args()

    if args.train == args.eval:
        raise SystemExit(
            "train and eval must be different captures: training on the capture you "
            "score measures memorisation, not detection. Pass --eval explicitly."
        )

    train = load_rows(args.train)
    print(f"train {args.train}: {len(train)} execs")

    rarity = features.build_rarity(train)
    features.apply_rarity(train, rarity)

    evaluation = load_rows(args.eval)
    features.apply_rarity(evaluation, rarity)
    manifest = read_manifest(args.manifest)
    labels, excluded = features.label(evaluation, manifest)
    subtrees, index = attack_subtrees(evaluation, manifest)
    if not subtrees:
        raise SystemExit(
            f"{args.eval}: no attack tags matched {args.manifest}. The eval capture "
            "must contain the attacks, otherwise there is no ground truth to score."
        )
    print(
        f"eval  {args.eval}: {len(evaluation)} execs, {sum(labels)} attack rows, "
        f"{sum(excluded)} harness rows excluded, {len(subtrees)} techniques"
    )

    train_x = np.asarray(features.vectorize(train), dtype=float)
    eval_x = np.asarray(features.vectorize(evaluation), dtype=float)

    if args.auc:
        auc(eval_x, labels, excluded)

    disguised = None
    if args.disguise:
        disguised = features.apply_rarity(features.disguise_rows(evaluation), rarity)
        disguised_x = np.asarray(features.vectorize(disguised), dtype=float)

    results = {}
    for name in args.models.split(","):
        train_scores, eval_scores, estimator, scaler = fit_score(name, train_x, eval_x)
        threshold = float(np.quantile(train_scores, 1 - args.fpr))
        d_pair = None
        if disguised is not None:
            scores = -estimator.score_samples(scaler.transform(disguised_x))
            d_tpr, d_fpr = report(
                f"{name} [disguised]",
                scores,
                threshold,
                labels,
                excluded,
                subtrees,
                index,
                evaluation,
            )
            d_pair = (d_tpr, d_fpr)
        tpr, fpr = report(
            name,
            eval_scores,
            threshold,
            labels,
            excluded,
            subtrees,
            index,
            evaluation,
            args.top,
        )
        results[name] = (tpr, fpr, d_pair, estimator, scaler, threshold)

    print(f"\n{'model':14s} {'TPR':>6s} {'FPR':>7s}   {'dTPR':>6s} {'dFPR':>7s}")
    for name, (tpr, fpr, d_pair, *_rest) in results.items():
        extra = f"   {d_pair[0]:6.3f} {d_pair[1]:7.4f}" if d_pair else ""
        print(f"{name:14s} {tpr:6.3f} {fpr:7.4f}{extra}")

    if args.save:
        best = max(results, key=lambda key: (results[key][0], -results[key][1]))
        _, _, _, estimator, scaler, threshold = results[best]
        joblib.dump(
            {
                "model": best,
                "estimator": estimator,
                "scaler": scaler,
                "threshold": threshold,
                "rarity": rarity,
                "features": features.FEATURES,
            },
            args.save,
        )
        print(f"\nsaved {best} to {args.save} (threshold {threshold:.4f})")


if __name__ == "__main__":
    main()
