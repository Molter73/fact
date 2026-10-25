#!/usr/bin/env -S uv run --script
#
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "pymongo==4.18.2"
# ]
# ///

"""Dump the FACT dataset DB to gzipped JSONL so captures can be reused
without regenerating traffic on the VM."""

import gzip
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from bson import json_util
from pymongo import MongoClient

MONGO_USER = os.environ.get("MONGO_INITDB_ROOT_USERNAME", "root")
MONGO_PASS = os.environ.get("MONGO_INITDB_ROOT_PASSWORD", "password")
URI = f"mongodb://{MONGO_USER}:{MONGO_PASS}@localhost:8082"

DUMPS = Path(__file__).resolve().parent / "dumps"


def main():
    if len(sys.argv) > 1:
        out = Path(sys.argv[1])
    else:
        stamp = datetime.now(timezone.utc).strftime("capture-%Y%m%dT%H%M%SZ")
        out = DUMPS / stamp
    out.mkdir(parents=True, exist_ok=True)

    with MongoClient(URI) as client:
        db = client.get_database("fact")
        for name in ["events", "processes"]:
            docs = 0
            path = out / f"{name}.jsonl.gz"
            with gzip.open(path, "wt", encoding="utf-8") as fh:
                for doc in db.get_collection(name).find({}):
                    fh.write(json_util.dumps(doc))
                    fh.write("\n")
                    docs += 1
            print(f"{name}: {docs} docs, {path.stat().st_size / 1e6:.2f} MB")

    print(f"dumped to {out}")


if __name__ == "__main__":
    main()
