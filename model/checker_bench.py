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

"""Replay captures through the streaming checker and report parity/quality."""

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import capture
import checker
import checker_reference
import features
import fingerprint

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
MANIFEST = ROOT / "dataset" / "attacks-manifest.jsonl"
MODEL = HERE / "model.joblib"

AMBIENT = ("dnf", "systemd", "fixfiles", "useradd")


@dataclass
class BenchmarkData:
    attacks: Path
    manifest: list
    scorer: checker.Scorer
    events: list
    processes: list
    rows: list
    labels: list
    excluded: list
    scores: list
    now: datetime


def read_manifest(path):
    if not path or not Path(path).is_file():
        return []
    with Path(path).open() as fh:
        return [json.loads(line) for line in fh if line.strip()]


def find_dump(explicit, names):
    if explicit:
        return Path(explicit)
    for name in names:
        path = ROOT / "dataset" / "dumps" / name
        if (path / "events.jsonl.gz").is_file():
            return path
    raise SystemExit(f"none of {names} found under dataset/dumps")


def event_key(event):
    value = event.get("_id")
    if isinstance(value, dict):
        return value.get("$oid") or str(value)
    return str(value)


def run_stream(events, processes, grace):
    engine = checker.CheckerEngine(
        processes,
        grace_ns=int(grace * 1e9),
        update_processes=False,
    )
    rows = []
    for event in sorted(events, key=event_key):
        engine.ingest(event)
        rows.extend(engine.flush(int(event["timestamp"])))
    rows.extend(engine.flush(0, force=True))
    return rows


def row_key(row):
    return int(row["upid"]), int(row["_exec_ts_ns"])


def compare_rows(batch_rows, stream_rows):
    batch = defaultdict(list)
    stream = defaultdict(list)
    for row in batch_rows:
        batch[row_key(row)].append(row)
    for row in stream_rows:
        stream[row_key(row)].append(row)
    keys = set(batch) | set(stream)
    missing = extra = feature_mismatches = path_mismatches = 0
    max_diff = 0.0
    for key in keys:
        left = batch.get(key, [])
        right = stream.get(key, [])
        missing += max(0, len(left) - len(right))
        extra += max(0, len(right) - len(left))
        for a, b in zip(left, right):
            for name in features.FEATURES:
                diff = abs(float(a[name]) - float(b[name]))
                max_diff = max(max_diff, diff)
                if diff > 1e-9:
                    feature_mismatches += 1
            if a["_paths"] != b["_paths"] or a["_dests"] != b["_dests"]:
                path_mismatches += 1
    return {
        "rows": len(batch_rows),
        "stream_rows": len(stream_rows),
        "missing": missing,
        "extra": extra,
        "feature_mismatches": feature_mismatches,
        "path_mismatches": path_mismatches,
        "max_diff": max_diff,
        "identical": missing == extra == feature_mismatches == path_mismatches == 0,
    }


def attack_subtrees(rows, manifest):
    parents = {}
    children = defaultdict(list)
    for row in rows:
        parents.setdefault(row["upid"], row["parent_upid"])
    for upid, parent in parents.items():
        children[parent].append(upid)
    index = defaultdict(list)
    for i, row in enumerate(rows):
        index[row["upid"]].append(i)
    subtrees = defaultdict(set)
    for entry in manifest:
        tag = entry["tag"]
        roots = {
            row["upid"]
            for row in rows
            if tag
            in " ".join([row["comm"], row["exe_path"], *row["args"], *row["_paths"]])
        }
        if roots:
            subtrees[entry["technique"]].update(features.descendants(roots, children))
    return subtrees, index


def alerts_from(rows, scores, threshold, strategy):
    memory = checker_reference.MemoryAlerts(strategy)
    for row, score in zip(rows, scores):
        if score >= threshold:
            memory.add(row, score, row["_host"])
    return memory


def fingerprint_report(
    rows, scores, threshold, strategy, labels, excluded, subtrees, index
):
    labels = list(labels)
    excluded = list(excluded)
    row_fps = [fingerprint.fingerprint(row, strategy) for row in rows]
    flagged = [score >= threshold for score in scores]
    ambient_rows = [
        i
        for i, (label, skip) in enumerate(zip(labels, excluded))
        if label == 0 and not skip
    ]
    ambient_fps = {row_fps[i] for i in ambient_rows if flagged[i]}
    alert_counts = defaultdict(int)
    memory = alerts_from(rows, scores, threshold, strategy)
    for doc in memory.docs.values():
        alert_counts[doc["fingerprint"]] = doc["count"]

    techniques = {}
    merged = 0
    for technique, members in sorted(subtrees.items()):
        indices = [i for upid in members for i in index.get(upid, ())]
        chosen = {row_fps[i] for i in indices if flagged[i]}
        overlap = chosen & ambient_fps
        merged += bool(overlap)
        techniques[technique] = {
            "rows": len(indices),
            "flagged": sum(1 for i in indices if flagged[i]),
            "fingerprints": len(chosen),
            "collapse_ratio": round(
                sum(1 for i in indices if flagged[i]) / max(1, len(chosen)), 3
            ),
            "ambient_merge": bool(overlap),
        }

    families = {}
    for family in AMBIENT:
        indices = [i for i in ambient_rows if rows[i]["comm"].startswith(family)]
        chosen = {row_fps[i] for i in indices if flagged[i]}
        counts = [alert_counts.get(fp, 0) for fp in chosen]
        families[family] = {
            "rows": len(indices),
            "flagged": sum(1 for i in indices if flagged[i]),
            "fingerprints": len(chosen),
            "max_count": max(counts, default=0),
            "collapse_ratio": round(
                sum(1 for i in indices if flagged[i]) / max(1, len(chosen)), 3
            ),
        }
    return {
        "techniques": techniques,
        "ambient": families,
        "attack_ambient_merges": merged,
        "distinct_attack_fingerprints": sum(
            item["fingerprints"] for item in techniques.values()
        ),
        "alerts": len(memory.docs),
    }


def compare_alerts(left, right):
    left_docs = {key: doc for key, doc in left.docs.items()}
    right_docs = {key: doc for key, doc in right.docs.items()}
    keys = set(left_docs) | set(right_docs)
    mismatches = []
    for key in sorted(keys):
        a = left_docs.get(key)
        b = right_docs.get(key)
        if a is None or b is None:
            mismatches.append(
                {
                    "key": key,
                    "reason": "missing" if a is None else "extra",
                }
            )
            continue
        fields = {}
        for field in (
            "count",
            "session_id",
            "basename_pattern",
            "last_basename_pattern",
        ):
            if a.get(field) != b.get(field):
                fields[field] = [a.get(field), b.get(field)]
        if abs(a.get("max_score", 0) - b.get("max_score", 0)) > 1e-9:
            fields["max_score"] = [a.get("max_score"), b.get("max_score")]
        if fields:
            mismatches.append({"key": key, "fields": fields})
    return {
        "alerts": len(left.docs),
        "stream_alerts": len(right.docs),
        "mismatches": mismatches[:20],
        "mismatch_count": len(mismatches),
        "identical": not mismatches,
    }


def compare_sessions(left, right, now, window, gate):
    a = left.rollup(now, window, gate)
    b = right.rollup(now, window, gate)
    a_map = {tuple(sorted(doc["_id"].items())): doc for doc in a}
    b_map = {tuple(sorted(doc["_id"].items())): doc for doc in b}
    keys = set(a_map) | set(b_map)
    mismatches = []
    for key in keys:
        first = a_map.get(key)
        second = b_map.get(key)
        if first is None or second is None:
            mismatches.append({"key": key, "reason": "missing"})
            continue
        if first["n_alerts"] != second["n_alerts"]:
            mismatches.append(
                {
                    "key": key,
                    "n_alerts": [first["n_alerts"], second["n_alerts"]],
                }
            )
    return {
        "sessions": len(a),
        "stream_sessions": len(b),
        "mismatches": mismatches[:20],
        "mismatch_count": len(mismatches),
        "identical": not mismatches,
    }


def parse_list(value):
    return [item.strip() for item in value.split(",") if item.strip()]


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--attacks", default=str(ROOT / "dataset" / "dumps" / "attacks")
    )
    parser.add_argument("--manifest", default=str(MANIFEST))
    parser.add_argument("--model", default=str(MODEL))
    parser.add_argument(
        "--fingerprints",
        default=",".join(fingerprint.STRATEGIES),
        help="comma-separated candidates",
    )
    parser.add_argument("--grace", default="10,30,60", help="comma-separated seconds")
    parser.add_argument(
        "--base-grace",
        type=float,
        default=30.0,
        help="grace used for the end-to-end comparison",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON only")
    parser.add_argument("--trend-window", type=float, default=3600.0)
    parser.add_argument("--burst-gate", type=int, default=3)
    return parser.parse_args(argv)


def load_benchmark(args):
    attacks = find_dump(args.attacks, ("attacks",))
    manifest = read_manifest(args.manifest)
    scorer = checker.Scorer.load(args.model)
    events, processes = capture.load_capture(attacks)
    rows = features.extract(events, processes)
    labels, excluded = features.label(rows, manifest)
    if not any(labels):
        raise SystemExit(f"{attacks}: no manifest tags matched")
    host = events[0]["hostname"]
    for row in rows:
        row["_host"] = host
    return BenchmarkData(
        attacks=attacks,
        manifest=manifest,
        scorer=scorer,
        events=events,
        processes=processes,
        rows=rows,
        labels=labels,
        excluded=excluded,
        scores=scorer.score(rows),
        now=max(checker.utc(row["_exec_ts_ns"]) for row in rows),
    )


def dataset_report(data):
    return {
        "attacks": str(data.attacks),
        "events": len(data.events),
        "processes": len(data.processes),
        "execs": len(data.rows),
        "attack_rows": sum(data.labels),
        "excluded_rows": sum(data.excluded),
        "threshold": data.scorer.threshold,
        "model": data.scorer.estimator.__class__.__name__,
    }


def grace_sweep(data, graces, base_grace):
    if base_grace not in graces:
        graces.append(base_grace)
    stream_by_grace = {}
    results = {}
    for grace in graces:
        stream_rows = run_stream(data.events, data.processes, grace)
        features.apply_rarity(stream_rows, data.scorer.rarity)
        stream_by_grace[grace] = stream_rows
        results[f"{grace:g}"] = compare_rows(data.rows, stream_rows)
    return stream_by_grace, results


def fingerprint_sweep(data, strategies):
    subtrees, index = attack_subtrees(data.rows, data.manifest)
    return {
        strategy: fingerprint_report(
            data.rows,
            data.scores,
            data.scorer.threshold,
            strategy,
            data.labels,
            data.excluded,
            subtrees,
            index,
        )
        for strategy in strategies
    }


def end_to_end(data, stream_rows, strategies, base_grace, window, gate):
    stream_scores = data.scorer.score(stream_rows)
    results = {}
    for strategy in strategies:
        batch_alerts = alerts_from(
            data.rows, data.scores, data.scorer.threshold, strategy
        )
        stream_alerts = alerts_from(
            stream_rows, stream_scores, data.scorer.threshold, strategy
        )
        results[strategy] = {
            "grace": base_grace,
            "alerts": compare_alerts(batch_alerts, stream_alerts),
            "sessions": compare_sessions(
                batch_alerts, stream_alerts, data.now, window, gate
            ),
        }
    return results


def build_report(args):
    data = load_benchmark(args)
    graces = [float(grace) for grace in parse_list(args.grace)]
    stream_by_grace, grace_results = grace_sweep(data, graces, args.base_grace)
    strategies = parse_list(args.fingerprints)
    return {
        "dataset": dataset_report(data),
        "grace_sweep": grace_results,
        "fingerprints": fingerprint_sweep(data, strategies),
        "end_to_end": end_to_end(
            data,
            stream_by_grace[args.base_grace],
            strategies,
            args.base_grace,
            args.trend_window,
            args.burst_gate,
        ),
    }


def print_report(report, base_grace):
    data = report["dataset"]
    print(f"Attack capture: {data['attacks']}")
    print(
        f"  events={data['events']}  processes={data['processes']}  "
        f"execs={data['execs']}  attack_rows={data['attack_rows']}  "
        f"excluded_rows={data['excluded_rows']}"
    )
    print(f"  model={data['model']}  threshold={data['threshold']:.4f}")
    print_grace_sweep(report["grace_sweep"])
    print_fingerprints(report["fingerprints"])
    print_end_to_end(report["end_to_end"], base_grace)


def print_grace_sweep(results):
    print("\n[1/3] Streaming vs batch feature parity")
    print("  grace   rows  missing  extra  feat_diff  path_diff  max_diff  result")
    for grace, result in results.items():
        status = "ok" if result["identical"] else "DIFF"
        print(
            f"  {grace:>4s}s {result['stream_rows']:5d} "
            f"{result['missing']:8d} {result['extra']:6d} "
            f"{result['feature_mismatches']:10d} "
            f"{result['path_mismatches']:9d} "
            f"{result['max_diff']:8.3g}  {status}"
        )


def print_fingerprints(results):
    print("\n[2/3] Fingerprint strategies")
    print("  strategy             alerts  attack_fps  merges  result")
    for strategy, result in results.items():
        status = "MERGE" if result["attack_ambient_merges"] else "ok"
        print(
            f"  {strategy:20s} {result['alerts']:6d} "
            f"{result['distinct_attack_fingerprints']:10d} "
            f"{result['attack_ambient_merges']:7d}  {status}"
        )

    for strategy, result in results.items():
        print(f"\n  {strategy} details")
        print("    technique             rows  flagged  fps  collapse  merge")
        for technique, item in result["techniques"].items():
            merge = "yes" if item["ambient_merge"] else "no"
            print(
                f"    {technique:20s} {item['rows']:5d} "
                f"{item['flagged']:8d} {item['fingerprints']:4d} "
                f"{item['collapse_ratio']:8.2f}  {merge}"
            )
        for family, item in result["ambient"].items():
            print(
                f"    ambient/{family:12s} {item['rows']:5d} "
                f"{item['flagged']:8d} {item['fingerprints']:4d} "
                f"{item['collapse_ratio']:8.2f}  "
                f"max_count={item['max_count']}"
            )


def print_end_to_end(results, base_grace):
    print(f"\n[3/3] End-to-end alerts and sessions (grace {base_grace:g}s)")
    print("  strategy             alerts  alert_diff  sessions  session_diff  result")
    for strategy, result in results.items():
        alerts = result["alerts"]
        sessions = result["sessions"]
        status = "ok" if alerts["identical"] and sessions["identical"] else "DIFF"
        print(
            f"  {strategy:20s} {alerts['alerts']:6d} "
            f"{alerts['mismatch_count']:10d} "
            f"{sessions['sessions']:8d} "
            f"{sessions['mismatch_count']:12d}  {status}"
        )


def main(argv=None):
    args = parse_args(argv)
    report = build_report(args)
    if args.json:
        json.dump(report, sys.stdout, indent=2, default=str)
        print()
    else:
        print_report(report, args.base_grace)


if __name__ == "__main__":
    main()
