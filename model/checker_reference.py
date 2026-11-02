"""In-memory reference implementation used by tests and the benchmark."""

from datetime import timedelta

import fingerprint
from checker import build_alert_upsert


def apply_update(doc, update):
    for key, value in update.get("$setOnInsert", {}).items():
        doc.setdefault(key, value)
    for key, value in update.get("$set", {}).items():
        doc[key] = value
    for key, value in update.get("$inc", {}).items():
        doc[key] = doc.get(key, 0) + value
    for key, value in update.get("$max", {}).items():
        if key not in doc or value > doc[key]:
            doc[key] = value
    for key, value in update.get("$addToSet", {}).items():
        values = doc.setdefault(key, [])
        if value not in values:
            values.append(value)
    return doc


class MemoryAlerts:
    def __init__(self, strategy=fingerprint.DEFAULT):
        self.strategy = strategy
        self.docs = {}

    def add(self, row, score, host):
        flt, update = build_alert_upsert(row, score, host, self.strategy)
        key = (flt["fingerprint"], flt["host"])
        doc = self.docs.setdefault(
            key, {"fingerprint": key[0], "host": key[1], "_id": f"{key[0]}:{key[1]}"}
        )
        apply_update(doc, update)
        return doc

    def rollup(self, now, window, burst_gate):
        return rollup_docs(self.docs.values(), now, window, burst_gate)


def rollup_docs(alerts, now, window, burst_gate):
    cutoff = now - timedelta(seconds=window)
    groups = {}
    for doc in alerts:
        if doc.get("status") == "whitelisted" or doc.get("last_ts", cutoff) < cutoff:
            continue
        key = (doc.get("host", ""), doc.get("session_id", 0))
        group = groups.setdefault(
            key,
            {
                "_id": {"host": key[0], "session_id": key[1]},
                "host": key[0],
                "session_id": key[1],
                "n_alerts": 0,
                "distinct_keys": set(),
                "max_score": doc.get("max_score", 0.0),
                "first_ts": doc.get("first_ts", now),
                "last_ts": doc.get("last_ts", now),
            },
        )
        group["n_alerts"] += doc.get("count", 0)
        group["distinct_keys"].add(doc.get("fingerprint", ""))
        group["max_score"] = max(group["max_score"], doc.get("max_score", 0.0))
        group["first_ts"] = min(group["first_ts"], doc.get("first_ts", now))
        group["last_ts"] = max(group["last_ts"], doc.get("last_ts", now))
    result = []
    for group in groups.values():
        if group["n_alerts"] < burst_gate:
            continue
        group["distinct_keys"] = sorted(group["distinct_keys"])
        result.append(group)
    return sorted(result, key=lambda doc: (-doc["n_alerts"], doc["_id"]["session_id"]))
