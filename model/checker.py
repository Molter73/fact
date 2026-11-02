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

"""Resident checker: poll FACT events, score Exec rows, collapse alerts."""

import argparse
import logging
import os
import signal
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import joblib
import numpy as np
from pymongo import ASCENDING, DESCENDING, MongoClient, UpdateOne
from pymongo.errors import PyMongoError

import features
import fingerprint

HERE = Path(__file__).resolve().parent
DEFAULT_MODEL = HERE / "model.joblib"
URI = os.environ.get("FACT_CHECKER_DB_URL")

log = logging.getLogger("checker")


def _env_float(name: str, default: float) -> float:
    value = os.environ.get(name)
    return float(value) if value is not None else default


def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    return int(value) if value is not None else default


@dataclass(frozen=True)
class Settings:
    mongo_uri: str = URI
    database: str = "fact"
    poll_interval: float = 1.0
    grace_seconds: float = 30.0
    flush_interval: float = 1.0
    rollup_interval: float = 60.0
    rollup_window: float = 3600.0
    burst_gate: int = 3
    alert_ttl_days: float = 7.0
    fingerprint: str = fingerprint.DEFAULT
    model: str = str(DEFAULT_MODEL)
    loglevel: str = "INFO"
    batch_size: int = 1000
    process_refresh: float = 15.0

    @classmethod
    def from_env(cls):
        return cls(
            mongo_uri=URI,
            database=os.environ.get("CHECKER_DB", "fact"),
            poll_interval=_env_float("CHECKER_POLL_INTERVAL", 1.0),
            grace_seconds=_env_float("CHECKER_GRACE_SECONDS", 30.0),
            flush_interval=_env_float("CHECKER_FLUSH_INTERVAL", 1.0),
            rollup_interval=_env_float("CHECKER_ROLLUP_INTERVAL", 60.0),
            rollup_window=_env_float("CHECKER_ROLLUP_WINDOW", 3600.0),
            burst_gate=_env_int("CHECKER_BURST_GATE", 3),
            alert_ttl_days=_env_float("CHECKER_ALERT_TTL_DAYS", 7.0),
            fingerprint=os.environ.get("CHECKER_FINGERPRINT", fingerprint.DEFAULT),
            model=os.environ.get("CHECKER_MODEL", str(DEFAULT_MODEL)),
            loglevel=os.environ.get("CHECKER_LOGLEVEL", "INFO"),
            batch_size=_env_int("CHECKER_BATCH_SIZE", 1000),
            process_refresh=_env_float("CHECKER_PROCESS_REFRESH", 15.0),
        )


def utc(ts_ns):
    return datetime.fromtimestamp(int(ts_ns) / 1e9, tz=UTC)


def resolve_cursor(state, replay):
    if replay or state is None or "last_id" not in state:
        return None
    return state["last_id"]


class ProcessCache:
    def __init__(self, docs=()):
        self.procs = {}
        self.load(docs)

    def load(self, docs):
        for doc in docs:
            upid = doc.get("upid")
            if upid is not None:
                self.procs[int(upid)] = dict(doc)

    def update(self, payload):
        if payload is not None and "upid" in payload:
            self.procs[int(payload["upid"])] = dict(payload)

    def ensure(self, upid, lookup=None):
        current = int(upid or 0)
        seen = set()
        while current and current not in seen:
            seen.add(current)
            proc = self.procs.get(current)
            if proc is None:
                if lookup is None:
                    break
                proc = lookup(current)
                if not proc:
                    break
                self.procs[current] = dict(proc)
            current = int(proc.get("parent_upid", 0))


@dataclass
class BufferedProcess:
    host: str
    upid: int
    execs: list = field(default_factory=list)
    net: list = field(default_factory=list)
    files: list = field(default_factory=list)
    last_event_ts: int = 0


@dataclass(frozen=True)
class EventBatch:
    count: int
    last_id: object
    max_ts: int


class CheckerEngine:
    def __init__(
        self,
        processes=(),
        grace_ns=30_000_000_000,
        lookup=None,
        update_processes=True,
    ):
        self.processes = ProcessCache(processes)
        self.grace_ns = int(grace_ns)
        self.lookup = lookup
        self.update_processes = update_processes
        self.siblings = features.SiblingBursts()
        self.buffers = {}

    def _buffer(self, host, upid):
        key = (host, int(upid))
        buffer = self.buffers.get(key)
        if buffer is None:
            buffer = BufferedProcess(host=host, upid=int(upid))
            self.buffers[key] = buffer
        return buffer

    @staticmethod
    def _touch(buffer, ts):
        buffer.last_event_ts = max(buffer.last_event_ts, ts)

    def _update_process_cache(self, data):
        if not self.update_processes:
            return

        payload = None
        if "Process" in data:
            proc = data["Process"]
            if "Fork" in proc:
                payload = proc["Fork"]["child"]
            elif "Exec" in proc:
                payload = proc["Exec"]
            else:
                payload = proc["Exit"]
        elif "Network" in data:
            payload = data["Network"]["process"]
        else:  # File in data
            payload = data["File"]["process"]

        self.processes.update(payload)

    def _ingest_process(self, process, host, ts):
        if "Exec" in process:
            payload = process["Exec"]
            buffer = self._buffer(host, payload["upid"])
            burst = self.siblings.record(payload.get("parent_upid", 0), ts)
            buffer.execs.append((ts, payload, burst))
            self._touch(buffer, ts)
        elif "Exit" in process:
            upid = int(process["Exit"].get("upid", 0))
            buffer = self.buffers.get((host, upid))
            if buffer:
                self._touch(buffer, ts)

    def _ingest_network(self, network, host, ts):
        payload = network.get("process", {})
        upid = int(payload.get("upid", 0))
        if not upid:
            return
        buffer = self._buffer(host, upid)
        buffer.net.append(network["network"])
        self._touch(buffer, ts)

    def _ingest_file(self, file_event, host, ts):
        payload = file_event.get("process", {})
        upid = int(payload.get("upid", 0))
        if not upid:
            return
        buffer = self._buffer(host, upid)
        buffer.files.append(file_event["file"])
        self._touch(buffer, ts)

    def ingest(self, event):
        data = event.get("data", {})
        host = event["hostname"]
        ts = int(event["timestamp"])
        self._update_process_cache(data)

        if "Process" in data:
            self._ingest_process(data["Process"], host, ts)
        elif "Network" in data:
            self._ingest_network(data["Network"], host, ts)
        else:  # "File" in data:
            self._ingest_file(data["File"], host, ts)

    def flush(self, watermark_ns, force=False):
        if force:
            keys = list(self.buffers)
        else:
            keys = [
                key
                for key, buffer in self.buffers.items()
                if watermark_ns - buffer.last_event_ts >= self.grace_ns
            ]
        rows = []
        for key in keys:
            buffer = self.buffers.pop(key)
            if not buffer.execs:
                continue
            self.processes.ensure(buffer.upid, self.lookup)
            for ts, payload, burst in sorted(buffer.execs, key=lambda item: item[0]):
                self.processes.ensure(payload.get("upid", 0), self.lookup)
                row = features.build_row(
                    ts,
                    payload,
                    self.processes.procs,
                    buffer.net,
                    buffer.files,
                    burst,
                )
                row["_host"] = buffer.host
                rows.append(row)
        rows.sort(key=lambda row: row["_exec_ts_ns"])
        return rows

    def pending(self):
        return len(self.buffers)


class Scorer:
    def __init__(self, artifact):
        self.rarity = artifact["rarity"]
        self.estimator = artifact["estimator"]
        self.scaler = artifact["scaler"]
        self.threshold = float(artifact["threshold"])
        self.features = list(artifact["features"])

    @classmethod
    def load(cls, path):
        return cls(joblib.load(path))

    def score(self, rows):
        if not rows:
            return []
        features.apply_rarity(rows, self.rarity)
        matrix = np.asarray(
            [[float(row[name]) for name in self.features] for row in rows], dtype=float
        )
        return (-self.estimator.score_samples(self.scaler.transform(matrix))).tolist()


def build_alert_upsert(row, score, host, strategy=fingerprint.DEFAULT):
    described = fingerprint.describe(row, strategy)
    fp = described["fingerprint"]
    pattern = described["basename_pattern"]
    ts = utc(row["_exec_ts_ns"])
    session = features.session_id(row)
    sample = {
        "comm": row["comm"],
        "parent": row["parent_comm"],
        "exe_path": row["exe_path"],
        "args": row["args"],
        "uid": row["uid"],
        "gid": row["gid"],
        "paths": row["_paths"][:8],
        "exec_ts_ns": row["_exec_ts_ns"],
    }
    return (
        {"fingerprint": fp, "host": host},
        {
            "$setOnInsert": {
                "first_ts": ts,
                "sample": sample,
                "status": "open",
                "basename_pattern": pattern,
                "session_id": session,
            },
            "$set": {"last_ts": ts, "last_basename_pattern": pattern},
            "$inc": {"count": 1},
            "$max": {"max_score": float(score)},
            "$addToSet": {"session_ids": session},
        },
    )


def rollup_pipeline(now, window, burst_gate):
    cutoff = now - timedelta(seconds=window)
    return [
        {"$match": {"last_ts": {"$gte": cutoff}, "status": {"$ne": "whitelisted"}}},
        {
            "$group": {
                "_id": {"host": "$host", "session_id": "$session_id"},
                "host": {"$first": "$host"},
                "session_id": {"$first": "$session_id"},
                "n_alerts": {"$sum": "$count"},
                "distinct_keys": {"$addToSet": "$fingerprint"},
                "max_score": {"$max": "$max_score"},
                "first_ts": {"$min": "$first_ts"},
                "last_ts": {"$max": "$last_ts"},
            }
        },
        {"$match": {"n_alerts": {"$gte": burst_gate}}},
        {"$set": {"updated_at": now}},
        {
            "$merge": {
                "into": "alerts_sessions",
                "on": "_id",
                "whenMatched": "replace",
                "whenNotMatched": "insert",
            }
        },
    ]


def wait_for_mongo(client, timeout=60):
    deadline = time.monotonic() + timeout
    while True:
        try:
            client.get_database("admin").command("ping")
            return
        except PyMongoError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


class Checker:
    def __init__(self, client, settings, scorer, engine):
        self.client = client
        self.settings = settings
        self.scorer = scorer
        self.engine = engine
        self.db = client.get_database(settings.database)
        self.events = self.db.get_collection("events")
        self.processes = self.db.get_collection("processes")
        self.alerts = self.db.get_collection("alerts")
        self.sessions = self.db.get_collection("alerts_sessions")
        self.watch_state = self.db.get_collection("watch_state")
        self.stop = threading.Event()
        self.now_ns = time.time_ns()
        self.now_dt = utc(self.now_ns)

    def ensure_indexes(self):
        self.alerts.create_index(
            [("fingerprint", ASCENDING), ("host", ASCENDING)],
            unique=True,
            name="fingerprint_host",
        )
        self.alerts.create_index(
            [("last_ts", ASCENDING)],
            expireAfterSeconds=int(self.settings.alert_ttl_days * 86400),
            name="ttl_last_ts",
        )
        self.sessions.create_index(
            [("last_ts", ASCENDING)],
            expireAfterSeconds=int(self.settings.alert_ttl_days * 86400),
            name="ttl_last_ts",
        )

    def wait_ready(self):
        wait_for_mongo(self.client)
        self.ensure_indexes()

    def save_cursor(self, last_id):
        self.watch_state.update_one(
            {"_id": "events"},
            {
                "$set": {
                    "last_id": last_id,
                    "last_flush": self.now_dt,
                    "updated_at": datetime.now(UTC),
                }
            },
            upsert=True,
        )

    def write_rows(self, rows):
        if not rows:
            return 0
        scores = self.scorer.score(rows)
        operations = []
        for row, score in zip(rows, scores):
            if score < self.scorer.threshold:
                continue
            host = row["_host"]
            flt, update = build_alert_upsert(
                row, score, host, self.settings.fingerprint
            )
            operations.append(UpdateOne(flt, update, upsert=True))
        if operations:
            self.alerts.bulk_write(operations, ordered=True)
        return len(operations)

    def refresh_processes(self):
        self.engine.processes.load(self.processes.find({}))
        log.debug("refreshed process cache: %d rows", len(self.engine.processes.procs))

    def rollup(self):
        now = self.now_dt
        list(
            self.alerts.aggregate(
                rollup_pipeline(
                    now, self.settings.rollup_window, self.settings.burst_gate
                )
            )
        )
        log.info(
            "rolled up alerts through %s (window %ss, gate %s)",
            now.isoformat(),
            self.settings.rollup_window,
            self.settings.burst_gate,
        )

    def _initial_cursor(self, replay):
        state = self.watch_state.find_one({"_id": "events"})
        last_id = resolve_cursor(state, replay)
        if replay or state is None or "last_id" not in state:
            self.save_cursor(last_id)
            log.info("initial cursor: %s", last_id)
        return last_id

    def _newest_id(self):
        newest = self.events.find_one(
            {}, sort=[("_id", DESCENDING)], projection={"_id": 1}
        )
        return newest["_id"] if newest else None

    def _read_batch(self, last_id):
        query = {} if last_id is None else {"_id": {"$gt": last_id}}
        events = (
            self.events.find(query)
            .sort("_id", ASCENDING)
            .limit(self.settings.batch_size)
        )
        count = 0
        batch_last_id = last_id
        max_ts = 0
        for event in events:
            count += 1
            batch_last_id = event["_id"]
            max_ts = max(max_ts, int(event["timestamp"]))
            self.engine.ingest(event)
        return EventBatch(count, batch_last_id, max_ts)

    def _flush(self, now_ns, force=False):
        self.now_ns = now_ns
        self.now_dt = utc(now_ns)
        return self.write_rows(self.engine.flush(now_ns, force=force))

    def _commit_batch(self, batch, now_ns):
        flagged = self._flush(now_ns)
        self.save_cursor(batch.last_id)
        log.debug("processed %d events, %d flagged", batch.count, flagged)

    def _run_periodic(self, last_flush, last_refresh, last_rollup, flush_ns=None):
        now = time.monotonic()
        if now - last_flush >= self.settings.flush_interval:
            self._flush(time.time_ns() if flush_ns is None else flush_ns)
            last_flush = now
        if now - last_refresh >= self.settings.process_refresh:
            self.refresh_processes()
            last_refresh = now
        if now - last_rollup >= self.settings.rollup_interval:
            self.rollup()
            last_rollup = now
        return last_flush, last_refresh, last_rollup

    def _catch_up(self, last_id, target_id):
        if target_id is None or (last_id is not None and last_id >= target_id):
            return last_id

        last_flush = 0.0
        last_refresh = last_rollup = time.monotonic()
        while not self.stop.is_set():
            batch = self._read_batch(last_id)
            if not batch.count:
                break
            self._commit_batch(batch, batch.max_ts)
            last_id = batch.last_id
            last_flush = time.monotonic()
            if last_id >= target_id:
                log.info("caught up at %s", last_id)
                break
            last_flush, last_refresh, last_rollup = self._run_periodic(
                last_flush, last_refresh, last_rollup, self.now_ns
            )
        return last_id

    def _follow(self, last_id):
        last_flush = 0.0
        last_refresh = last_rollup = time.monotonic()
        while not self.stop.is_set():
            batch = self._read_batch(last_id)
            if batch.count:
                self._commit_batch(batch, time.time_ns())
                last_id = batch.last_id
                last_flush = time.monotonic()
                if batch.count == self.settings.batch_size:
                    continue
            last_flush, last_refresh, last_rollup = self._run_periodic(
                last_flush, last_refresh, last_rollup
            )
            self.stop.wait(self.settings.poll_interval)
        return last_id

    def _finalize(self, last_id):
        self._flush(time.time_ns(), force=True)
        self.save_cursor(last_id)
        self.rollup()

    def run(self, replay=False, once=False):
        self.wait_ready()
        last_id = self._initial_cursor(replay)
        last_id = self._catch_up(last_id, self._newest_id())
        if not once:
            last_id = self._follow(last_id)
        self._finalize(last_id)


def print_trend(alerts, days=1.0, limit=20):
    since = datetime.now(UTC) - timedelta(days=days)
    pipeline = [
        {"$match": {"last_ts": {"$gte": since}}},
        {
            "$group": {
                "_id": {"fingerprint": "$fingerprint", "host": "$host"},
                "count": {"$sum": "$count"},
                "max_score": {"$max": "$max_score"},
                "last_ts": {"$max": "$last_ts"},
                "status": {"$first": "$status"},
            }
        },
        {"$sort": {"count": DESCENDING, "max_score": DESCENDING}},
        {"$limit": limit},
    ]
    print(f"{'count':>6s} {'score':>8s} {'last_ts':<25s} {'status':<11s} fingerprint")
    for doc in alerts.aggregate(pipeline):
        print(
            f"{doc['count']:6d} {doc['max_score']:8.3f} "
            f"{doc['last_ts'].isoformat():<25s} {doc.get('status', ''):<11s} "
            f"{doc['_id']['fingerprint']}"
        )


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--replay",
        action="store_true",
        help="re-score all available events from the oldest, ignoring the cursor",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="catch up to the newest available event and exit (for smoke tests)",
    )
    parser.add_argument(
        "--trend",
        action="store_true",
        help="print the top offenders over --trend-days and exit",
    )
    parser.add_argument("--trend-days", type=float, default=1.0)
    parser.add_argument("--trend-limit", type=int, default=20)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    settings = Settings.from_env()
    logging.basicConfig(
        level=getattr(logging, settings.loglevel.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    if settings.fingerprint not in fingerprint.STRATEGIES:
        raise ValueError(f"unknown fingerprint strategy: {settings.fingerprint}")
    with MongoClient(
        settings.mongo_uri, serverSelectionTimeoutMS=5000, tz_aware=True
    ) as client:
        wait_for_mongo(client)
        db = client.get_database(settings.database)
        if args.trend:
            print_trend(
                db.get_collection("alerts"),
                args.trend_days,
                args.trend_limit,
            )
            return

        scorer = Scorer.load(settings.model)
        proc_collection = db.get_collection("processes")
        processes = list(proc_collection.find({}))
        engine = CheckerEngine(
            processes,
            grace_ns=int(settings.grace_seconds * 1e9),
            lookup=lambda upid: proc_collection.find_one({"upid": upid}),
        )
        checker = Checker(client, settings, scorer, engine)

        def stop(_signum, _frame):
            checker.stop.set()

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        checker.run(replay=args.replay, once=args.once)


if __name__ == "__main__":
    main()
