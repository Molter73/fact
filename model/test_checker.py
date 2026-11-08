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
"""Unit tests for checker helpers that do not need a live MongoDB."""

import math
import unittest
from datetime import UTC, datetime, timedelta

import checker
import checker_reference
import features
import fingerprint


def process(upid, comm, parent=0, uid=0):
    return {
        "upid": upid,
        "parent_upid": parent,
        "comm": comm,
        "args": [comm],
        "exe_path": f"/usr/bin/{comm}",
        "uid": uid,
        "gid": 0,
        "login_uid": 1000,
        "in_root_mount_ns": True,
    }


def row_for(payload, procs, files=(), net=(), ts=1_700_000_000_000_000_000):
    return features.build_row(ts, payload, procs, list(net), list(files))


class FingerprintTests(unittest.TestCase):
    def test_templates_normalize_volatile_names(self):
        self.assertEqual(
            fingerprint.basename_pattern("/tmp/atk-x-123-7.php"), "<tag>.php"
        )
        self.assertEqual(
            fingerprint.basename_pattern("/tmp/report-123456789.txt"), "report-<n>.txt"
        )
        self.assertEqual(
            fingerprint.path_template("/etc/cron.d/atk-x-1-2"), "/etc/cron.d/<name>"
        )
        self.assertEqual(fingerprint.path_template("/tmp/a.tar.gz"), "/tmp/<name>.gz")
        self.assertEqual(
            fingerprint.path_template(
                "/usr/share/wordpress/wp-content/uploads/2026/11/photo.jpg"
            ),
            "/usr/share/wordpress/wp-content/uploads/<year>/<month>/<name>.jpg",
        )
        self.assertEqual(
            fingerprint.basename_pattern("/tmp/rpm-tmp.Z4ziBW"), "rpm-tmp.<tmp>"
        )
        self.assertEqual(fingerprint._argv_token("/proc/12345/exe"), "/proc/<n>/<name>")

    def test_candidates_differ_and_stay_stable(self):
        row = {
            "comm": "cp",
            "parent_comm": "sudo",
            "args": ["cp", "/tmp/atk-a-1-2", "/etc/cron.d/atk-a-1-2"],
            "_paths": ["/etc/cron.d/atk-a-1-2"],
        }
        other = dict(row)
        other["_paths"] = ["/etc/cron.d/other"]
        other["args"] = ["cp", "--force", "/tmp/other", "/etc/cron.d/other"]
        values = {
            name: fingerprint.fingerprint(row, name) for name in fingerprint.STRATEGIES
        }
        self.assertEqual(len(set(values.values())), len(values))
        self.assertEqual(
            fingerprint.fingerprint(row, "comm_parent_path"),
            fingerprint.fingerprint(other, "comm_parent_path"),
        )
        self.assertNotEqual(
            fingerprint.fingerprint(row, "comm_parent_argv"),
            fingerprint.fingerprint(other, "comm_parent_argv"),
        )
        self.assertIn("<tag>", fingerprint.describe(row)["basename_pattern"])


class SessionTests(unittest.TestCase):
    def test_nearest_session_daemon(self):
        procs = {
            1: process(1, "sshd"),
            2: process(2, "sshd-session", 1),
            3: process(3, "bash", 2, uid=1000),
        }
        row = row_for(process(3, "bash", 2, uid=1000), procs)
        self.assertEqual(features.session_id(row), 2)

    def test_php_worker_is_a_session(self):
        procs = {
            10: process(10, "php-fpm"),
            11: process(11, "sh", 10, uid=48),
        }
        row = row_for(process(11, "sh", 10, uid=48), procs)
        self.assertEqual(features.session_id(row), 10)

    def test_lineage_prefers_exec_parent_over_snapshot(self):
        procs = {
            1: process(1, "systemd"),
            2: process(2, "sshd-session", 1),
            3: process(3, "systemd"),
            4: process(4, "bash", 3, uid=1000),
        }
        payload = process(4, "bash", 2, uid=1000)
        row = features.build_row(1, payload, procs, [], [], exec_procs={4: payload})
        self.assertEqual(row["parent_comm"], "sshd-session")
        self.assertEqual(row["_ancestors"][0], (2, "sshd-session"))


class FeatureTests(unittest.TestCase):
    def test_package_manager_activity_is_gated(self):
        procs = {
            1: process(1, "bash", 0, uid=1000),
            2: process(2, "sudo", 1, uid=1000),
            3: process(3, "dnf", 2, uid=0),
        }
        payload = process(3, "dnf", 2, uid=0)
        net = [
            {
                "Connect": {
                    "remote": {
                        "addr": {"V4": [203, 0, 113, 5]},
                        "port": 443,
                    }
                }
            }
        ]
        files = [
            {"Creation": {"filename": "/usr/bin/tool"}},
            {"Creation": {"filename": "/etc/tool.conf"}},
        ]
        row = row_for(payload, procs, files=files, net=net)
        self.assertEqual(row["package_ctx"], 1)
        self.assertEqual(row["n_connect"], 0)
        self.assertEqual(row["n_file_create"], 0)
        self.assertEqual(row["n_file_sysbin_nonpkg"], 0)
        self.assertEqual(row["n_file_sensitive_nonpkg"], 0)

    def test_security_features(self):
        procs = {1: process(1, "bash", 0, uid=1000)}
        payload = process(1, "tee", 0, uid=1000)
        files = [
            {"Creation": {"filename": "/etc/cron.d/job"}},
            {"Creation": {"filename": "/usr/share/wordpress/wp-content/x.php"}},
            {
                "Chmod": {
                    "inner": {"filename": "/usr/bin/tool"},
                    "new_mode": 0o4755,
                }
            },
        ]
        row = row_for(payload, procs, files=files)
        self.assertEqual(row["n_file_autostart"], math.log1p(1))
        self.assertEqual(row["n_file_webshell"], math.log1p(1))
        self.assertEqual(row["n_setuid"], math.log1p(1))

    def test_volatile_values_do_not_change_features(self):
        procs = {1: process(1, "bash", 0, uid=1000)}

        def make(url, path):
            payload = {**process(2, "curl", 1, 1000), "args": ["curl", url]}
            files = [{"Creation": {"filename": path}}]
            return features.build_row(1, payload, procs, [], files)

        left = make(
            "http://10.10.0.10/atk-curl-1-1",
            "/usr/share/wordpress/wp-content/uploads/2026/11/photo-123456.jpg",
        )
        right = make(
            "http://10.10.0.10/atk-curl-9-9",
            "/usr/share/wordpress/wp-content/uploads/2025/10/photo-654321.jpg",
        )
        rarity = features.build_rarity([left])
        features.apply_rarity([left, right], rarity)
        self.assertEqual(
            [left[name] for name in features.FEATURES],
            [right[name] for name in features.FEATURES],
        )

    def test_depth_is_not_a_feature(self):
        self.assertNotIn("depth", features.FEATURES)
        self.assertNotIn("depth_from_session", features.FEATURES)


class EngineTests(unittest.TestCase):
    def test_multiple_execs_share_buffered_events(self):
        procs = [process(1, "bash", 0, 1000), process(2, "env", 1, 1000)]
        engine = checker.CheckerEngine(procs, grace_ns=0)
        events = [
            {
                "hostname": "host",
                "timestamp": 10,
                "data": {"Process": {"Exec": process(2, "env", 1, 1000)}},
            },
            {
                "hostname": "host",
                "timestamp": 11,
                "data": {"Process": {"Exec": process(2, "php", 1, 1000)}},
            },
            {
                "hostname": "host",
                "timestamp": 12,
                "data": {
                    "File": {
                        "process": process(2, "php", 1, 1000),
                        "file": {"Creation": {"filename": "/tmp/created"}},
                    }
                },
            },
        ]
        for event in events:
            engine.ingest(event)
        rows = engine.flush(0, force=True)
        self.assertEqual([row["comm"] for row in rows], ["env", "php"])
        self.assertTrue(all(row["n_file_create"] == math.log1p(1) for row in rows))
        self.assertTrue(all(row["_host"] == "host" for row in rows))

    def test_grace_keeps_recent_buffer(self):
        procs = [process(1, "bash", 0, 1000)]
        engine = checker.CheckerEngine(procs, grace_ns=100)
        engine.ingest(
            {
                "hostname": "host",
                "timestamp": 10,
                "data": {"Process": {"Exec": process(1, "bash", 0, 1000)}},
            }
        )
        self.assertEqual(engine.flush(50), [])
        self.assertEqual(len(engine.flush(110)), 1)


class AlertTests(unittest.TestCase):
    def test_upsert_does_not_conflict_on_max_score(self):
        procs = {1: process(1, "bash", 0, 1000)}
        row = row_for(process(1, "bash", 0, 1000), procs)
        flt, update = checker.build_alert_upsert(row, 3.5, "host")
        self.assertEqual(flt, {"fingerprint": flt["fingerprint"], "host": "host"})
        self.assertNotIn("max_score", update["$setOnInsert"])
        self.assertEqual(update["$inc"], {"count": 1})
        self.assertEqual(update["$max"], {"max_score": 3.5})
        doc = checker_reference.apply_update({}, update)
        checker_reference.apply_update(doc, update)
        self.assertEqual(doc["count"], 2)
        self.assertEqual(doc["max_score"], 3.5)
        self.assertEqual(doc["status"], "open")

    def test_rollup_groups_by_host_and_session(self):
        now = datetime(2026, 1, 1, tzinfo=UTC)
        alerts = [
            {
                "host": "a",
                "session_id": 1,
                "fingerprint": "x",
                "count": 2,
                "max_score": 4.0,
                "first_ts": now - timedelta(minutes=2),
                "last_ts": now - timedelta(minutes=1),
            },
            {
                "host": "b",
                "session_id": 1,
                "fingerprint": "y",
                "count": 1,
                "max_score": 3.0,
                "first_ts": now - timedelta(minutes=2),
                "last_ts": now - timedelta(minutes=1),
            },
            {
                "host": "a",
                "session_id": 1,
                "fingerprint": "z",
                "count": 1,
                "max_score": 2.0,
                "first_ts": now - timedelta(minutes=2),
                "last_ts": now - timedelta(minutes=1),
            },
        ]
        result = checker_reference.rollup_docs(alerts, now, 3600, 3)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["_id"], {"host": "a", "session_id": 1})
        self.assertEqual(result[0]["n_alerts"], 3)
        self.assertEqual(result[0]["distinct_keys"], ["x", "z"])


class CursorTests(unittest.TestCase):
    def test_resolve_cursor(self):
        self.assertIsNone(checker.resolve_cursor(None, False))
        self.assertEqual(checker.resolve_cursor({"last_id": "old"}, False), "old")
        self.assertIsNone(checker.resolve_cursor({"last_id": "old"}, True))


if __name__ == "__main__":
    unittest.main()
