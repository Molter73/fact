"""Load FACT captures from a gzipped-JSONL dump directory or the live DB."""

import gzip
import json
import os
from pathlib import Path

URI = "mongodb://{user}:{pw}@localhost:8082"

LIVE = {"db", "live", "mongo"}


def load_capture(source, database="fact"):
    if source in LIVE:
        return _from_db(database)
    path = Path(source)
    if not (path / "events.jsonl.gz").is_file():
        raise SystemExit(f"{path}: not a dump directory (no events.jsonl.gz)")
    return _from_dump(path)


def _from_dump(path):
    def rows(name):
        with gzip.open(path / f"{name}.jsonl.gz", "rt", encoding="utf-8") as fh:
            return [json.loads(line) for line in fh]

    return rows("events"), rows("processes")


def _from_db(database):
    from pymongo import MongoClient
    from pymongo.errors import PyMongoError

    uri = URI.format(
        user=os.environ.get("MONGO_INITDB_ROOT_USERNAME", "root"),
        pw=os.environ.get("MONGO_INITDB_ROOT_PASSWORD", "password"),
    )
    try:
        with MongoClient(uri, serverSelectionTimeoutMS=5000) as client:
            db = client.get_database(database)
            return (
                list(db.get_collection("events").find({})),
                list(db.get_collection("processes").find({})),
            )
    except PyMongoError as exc:
        raise SystemExit(
            f"cannot read the live DB at {uri.split('@')[-1]}: {exc}"
        ) from exc
