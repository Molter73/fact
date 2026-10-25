"""Feature extraction over one row per Exec.

`upid` is used only to join lineage and events; it is never a feature.
"""

import re
from collections import Counter, defaultdict, deque
from math import log

DAEMONS = {
    "systemd",
    "init",
    "sshd",
    "php-fpm",
    "httpd",
    "nginx",
    "mariadbd",
    "mysqld",
    "redis-server",
}

SENSITIVE_DIRS = ("/etc/", "/root/", "/boot/", "/var/spool/cron/", "/usr/lib/systemd/")
SYSTEM_BIN_DIRS = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/local/bin/")
WEBROOT = "/usr/share/wordpress/"

PACKAGE_MANAGERS = {
    "dnf",
    "dnf5",
    "rpm",
    "yum",
    "microdnf",
    "apt",
    "apt-get",
    "dpkg",
    "zypper",
    "pip",
    "pip3",
    "gem",
    "cargo",
    "npm",
}

SIBLING_WINDOW_NS = 10_000_000_000

SHELL_META = (";", "&&", "||", "$(", "`", "|")
REDIRECT = (">", "<")

INODE_SUFFIX = re.compile(r";[0-9a-f]{6,}$")

RARITY_FEATURES = (
    "comm_rarity",
    "exe_rarity",
    "pair_rarity",
    "argv_rarity",
    "argv_excess",
    "dir_rarity",
    "comm_dir_rarity",
    "path_rarity",
    "dest_rarity",
    "ext_rarity",
    "ext_comm_rarity",
)

FEATURES = [
    "depth",
    "uid",
    "gid",
    "is_root",
    "uid_delta",
    "in_root_mount_ns",
    "login_uid_set",
    "n_args",
    "arg_bytes",
    "has_abs_arg",
    "has_shell_meta",
    "has_redirect",
    "has_pipe",
    "self_is_sudo",
    "parent_is_root",
    "parent_uid",
    "n_connect",
    "n_accept",
    "n_connect_nonloop",
    "n_remote_ports",
    "n_remote_hosts",
    "n_file_create",
    "n_file_unlink",
    "n_file_chmod",
    "n_file_chown",
    "n_file_rename",
    "n_file_open",
    "n_file_xattr",
    "n_file_sensitive",
    "n_file_system_bin",
    "n_file_webroot",
    "n_file_sysbin_nonpkg",
    "n_setuid",
    "sibling_burst",
    "unseen_comm",
    "unseen_pair",
    *RARITY_FEATURES,
]


def extract(events, processes):
    procs = {p["upid"]: p for p in processes}
    net = defaultdict(list)
    files = defaultdict(list)
    execs = []

    for ev in events:
        data = ev["data"]
        if "Process" in data:
            if "Exec" in data["Process"]:
                execs.append((ev["timestamp"], data["Process"]["Exec"]))
        elif "Network" in data:
            net[data["Network"]["process"]["upid"]].append(data["Network"]["network"])
        elif "File" in data:
            files[data["File"]["process"]["upid"]].append(data["File"]["file"])

    execs.sort(key=lambda item: item[0])
    bursts = _sibling_bursts(execs)
    return [
        _row(payload, procs, net[payload["upid"]], files[payload["upid"]], burst)
        for (_, payload), burst in zip(execs, bursts)
    ]


def _sibling_bursts(execs):
    """Execs sharing a parent within ±SIBLING_WINDOW_NS of each other.

    Ten busy children in ten seconds reads differently than the same children
    spread over a maintenance cycle."""
    recent = defaultdict(deque)
    bursts = [0] * len(execs)
    for index, (ts, payload) in enumerate(execs):
        window = recent[payload["parent_upid"]]
        while window and ts - window[0] > SIBLING_WINDOW_NS:
            window.popleft()
        bursts[index] = len(window)
        window.append(ts)
    return bursts


def lineage(upid, procs):
    chain = []
    seen = set()
    current = procs.get(upid, {}).get("parent_upid")
    while current and current not in seen:
        seen.add(current)
        parent = procs.get(current)
        if not parent:
            break
        chain.append(parent)
        current = parent.get("parent_upid")
    return chain


def _addr(value):
    if not isinstance(value, dict):
        return None
    for family in ("V4", "V6"):
        if family in value:
            return tuple(value[family])
    return None


def _is_loopback(addr):
    if not addr:
        return False
    return (
        addr[0] == 127 if len(addr) == 4 else addr[:-1] == (0,) * 15 and addr[-1] == 1
    )


def _paths(node):
    """Extract the paths touched by a file op.

    Chmod/Chown/xattr nest the payload under `inner`; Rename nests it under
    `new`/`old`, whence both the destination and the staging path are kept."""
    if "new" in node or "old" in node:
        nodes = (node["new"], node["old"])
    else:
        if "inner" in node:
            node = node["inner"]
        nodes = (node,)
    out = []
    for item in nodes:
        path = item.get("filename") or item.get("host_file") or ""
        if path:
            out.append(INODE_SUFFIX.sub("", path))
    return list(dict.fromkeys(out))


def _ext(path):
    base = path.rsplit("/", 1)[-1]
    if "." not in base:
        return ""
    return "." + base.rsplit(".", 1)[1].lower()


def _row(payload, procs, net, files, burst=0):
    comm = payload.get("comm") or ""
    exe = payload.get("exe_path") or ""
    args = [a for a in (payload.get("args") or []) if isinstance(a, str)]
    uid = payload.get("uid") or 0

    ancestors = lineage(payload["upid"], procs)
    parent = ancestors[0] if ancestors else {}
    parent_comm = parent.get("comm") or ""
    ancestor_comms = {a.get("comm") or "" for a in ancestors}
    package_ctx = bool((ancestor_comms | {comm}) & PACKAGE_MANAGERS)

    connects = accepts = nonloop = 0
    ports = set()
    hosts = set()
    dests = []
    for group in net:
        for op, node in group.items():
            if op == "Connect":
                remote = node.get("remote") or {}
                port = remote.get("port") or 0
                if not port:
                    continue
                addr = _addr(remote.get("addr"))
                connects += 1
                ports.add(port)
                hosts.add(addr)
                nonloop += 0 if _is_loopback(addr) else 1
                dests.append(f"{addr}:{port}")
            elif op == "Accept":
                accepts += 1

    ops = Counter()
    paths = []
    sensitive = system_bin = webroot = setuid = 0
    sysbin_nonpkg = 0
    for group in files:
        for op, node in group.items():
            ops[op] += 1
            if op == "Chmod" and int(node.get("new_mode") or 0) & 0o4000:
                setuid += 1
            for target in _paths(node):
                paths.append(target)
                sensitive += target.startswith(SENSITIVE_DIRS)
                system_bin += target.startswith(SYSTEM_BIN_DIRS)
                webroot += target.startswith(WEBROOT)
                sysbin_nonpkg += int(
                    target.startswith(SYSTEM_BIN_DIRS) and not package_ctx
                )

    args_text = args[1:]
    login_uid = payload.get("login_uid")
    dirs = sorted({p.rsplit("/", 1)[0] for p in paths if "/" in p})
    exts = sorted({_ext(p) for p in paths})
    return {
        "upid": payload["upid"],
        "parent_upid": payload.get("parent_upid") or 0,
        "comm": comm,
        "parent_comm": parent_comm,
        "exe_path": exe,
        "args": args,
        "depth": len(ancestors),
        "uid": uid,
        "gid": payload.get("gid") or 0,
        "is_root": int(uid == 0),
        "uid_delta": uid - (parent.get("uid") if parent else uid),
        "in_root_mount_ns": int(bool(payload.get("in_root_mount_ns"))),
        "login_uid_set": int(login_uid not in (None, 4294967295)),
        "n_args": len(args),
        "arg_bytes": log(1 + sum(len(a) for a in args)),
        "has_abs_arg": int(any(a.startswith("/") for a in args_text)),
        "has_shell_meta": int(any(m in a for a in args_text for m in SHELL_META)),
        "has_redirect": int(any(m in a for a in args_text for m in REDIRECT)),
        "has_pipe": int(any("|" in a for a in args_text)),
        "self_is_sudo": int(comm == "sudo"),
        "parent_is_root": int((parent.get("uid") or 0) == 0),
        "parent_uid": parent.get("uid") or 0,
        "n_connect": connects,
        "n_accept": accepts,
        "n_connect_nonloop": nonloop,
        "n_remote_ports": len(ports),
        "n_remote_hosts": len(hosts),
        "n_file_create": ops["Creation"],
        "n_file_unlink": ops["Unlink"],
        "n_file_chmod": ops["Chmod"],
        "n_file_chown": ops["Chown"],
        "n_file_rename": ops["Rename"],
        "n_file_open": ops["Open"],
        "n_file_xattr": ops["SetXattr"] + ops["RemoveXattr"],
        "n_file_sensitive": int(sensitive),
        "n_file_system_bin": int(system_bin),
        "n_file_webroot": int(webroot),
        "n_file_sysbin_nonpkg": int(sysbin_nonpkg),
        "n_setuid": setuid,
        "sibling_burst": burst,
        "_paths": paths,
        "_dests": dests,
        "_dirs": dirs,
        "_exts": exts,
        "_ext_comm": [f"{comm}|{e}" for e in exts],
        "_comm_dir": [f"{comm}|{d}" for d in dirs],
        "_pair": f"{parent_comm}|{comm}",
        "_argv": f"{comm}\x00" + "\x00".join(args_text),
        "_ancestors": [(a["upid"], a.get("comm") or "") for a in ancestors],
    }


def _keyed(row, key):
    value = row[key]
    return value if isinstance(value, list) else [value]


def build_rarity(rows):
    tables = {
        key: Counter(v for r in rows for v in _keyed(r, key))
        for key in (
            "comm",
            "parent_comm",
            "exe_path",
            "_pair",
            "_argv",
            "_dirs",
            "_paths",
            "_dests",
            "_exts",
            "_ext_comm",
            "_comm_dir",
        )
    }
    totals = {key: sum(table.values()) or 1 for key, table in tables.items()}
    model = {"tables": tables, "totals": totals}

    argv_totals = defaultdict(float)
    argv_counts = Counter()
    for row in rows:
        argv_totals[row["comm"]] += _score(model, "_argv", row["_argv"])
        argv_counts[row["comm"]] += 1
    model["comm_argv_mean"] = {
        comm: argv_totals[comm] / n for comm, n in argv_counts.items()
    }
    model["argv_mean"] = sum(argv_totals.values()) / max(1, argv_counts.total())
    return model


def _score(model, key, value):
    return -log((model["tables"][key].get(value, 0) + 0.5) / model["totals"][key])


def apply_rarity(rows, model):
    for row in rows:
        row["comm_rarity"] = _score(model, "comm", row["comm"])
        row["parent_comm_rarity"] = _score(model, "parent_comm", row["parent_comm"])
        row["exe_rarity"] = _score(model, "exe_path", row["exe_path"])
        row["pair_rarity"] = _score(model, "_pair", row["_pair"])
        row["argv_rarity"] = _score(model, "_argv", row["_argv"])
        row["argv_excess"] = row["argv_rarity"] - model["comm_argv_mean"].get(
            row["comm"], model["argv_mean"]
        )
        row["dir_rarity"] = max(
            (_score(model, "_dirs", d) for d in row["_dirs"]), default=0.0
        )
        row["comm_dir_rarity"] = max(
            (_score(model, "_comm_dir", d) for d in row["_comm_dir"]), default=0.0
        )
        row["path_rarity"] = max(
            (_score(model, "_paths", p) for p in row["_paths"]), default=0.0
        )
        row["dest_rarity"] = max(
            (_score(model, "_dests", d) for d in row["_dests"]), default=0.0
        )
        row["ext_rarity"] = max(
            (_score(model, "_exts", e) for e in row["_exts"]), default=0.0
        )
        row["ext_comm_rarity"] = max(
            (_score(model, "_ext_comm", e) for e in row["_ext_comm"]), default=0.0
        )
        row["unseen_comm"] = int(model["tables"]["comm"].get(row["comm"], 0) == 0)
        row["unseen_pair"] = int(model["tables"]["_pair"].get(row["_pair"], 0) == 0)
    return rows


def vectorize(rows):
    return [[float(r[f]) for f in FEATURES] for r in rows]


def label(rows, manifest):
    """Split the evaluation capture into attack rows, benign rows, and harness
    scaffolding that belongs to neither.

    Attack rows are tagged processes and their descendants. Scaffolding is the
    rest of the attack script's subtree (`date`, `hostname`, `sleep`, ...),
    which is neither benign traffic nor an attack action. The script root is the
    topmost non-daemon ancestor, so php-fpm never adopts a webshell's siblings."""
    tags = [entry["tag"] for entry in manifest]
    if not tags:
        return [0] * len(rows), [False] * len(rows)

    parents = {}
    ancestors = {}
    for row in rows:
        parents.setdefault(row["upid"], row["parent_upid"])
        ancestors.setdefault(row["upid"], row["_ancestors"])

    tagged = set()
    for row in rows:
        blob = " ".join([row["comm"], row["exe_path"], *row["args"], *row["_paths"]])
        if any(tag in blob for tag in tags):
            tagged.add(row["upid"])
    if not tagged:
        return [0] * len(rows), [False] * len(rows)

    children = defaultdict(list)
    for upid, parent in parents.items():
        children[parent].append(upid)

    attack = descendants(tagged, children)
    harness = {_script_root(upid, ancestors) for upid in tagged}
    scaffolding = descendants(harness, children) - attack
    return (
        [int(row["upid"] in attack) for row in rows],
        [row["upid"] in scaffolding for row in rows],
    )


def descendants(upids, children):
    members = set(upids)
    queue = list(upids)
    while queue:
        for child in children.get(queue.pop(), ()):
            if child not in members:
                members.add(child)
                queue.append(child)
    return members


def _script_root(upid, ancestors):
    """Topmost ancestor that is not a daemon."""
    root = upid
    for candidate, comm in ancestors.get(upid, ()):
        if comm in DAEMONS:
            break
        root = candidate
    return root


TAG = re.compile(r"atk-([a-z_0-9]+)-(\d+)-(\d+)")

DISGUISE_NAMES = {
    "persist_cron": "cron-report",
    "persist_systemd": "unit-check",
    "persist_sshd": "config-gen",
    "tamper_binary": "bin-backup",
    "setuid_drop": "perm-sync",
    "webshell_drop": "plugin-scan",
    "webshell_exec": "plugin-probe",
    "reverse_shell": "conn-check",
    "curl_pipe_sh": "update-fetch",
    "exfil_connect": "metrics-push",
    "cred_read": "audit-scan",
}


def _disguise(match):
    technique, epoch, token = match.groups()
    name = DISGUISE_NAMES.get(technique, technique.replace("_", "-"))
    return f"{name}-{epoch}-{token}"


def disguise_rows(rows):
    """Rename atk-* artifacts to benign-looking names.

    Detection must survive this: if the disguised scores collapse, the model is
    reading the harness tags, not the behaviour."""
    out = []
    for row in rows:
        if not any(TAG.search(s) for s in [row["comm"], row["exe_path"], *row["args"]]):
            out.append(row)
            continue
        copy = dict(row)
        copy["args"] = [TAG.sub(_disguise, a) for a in row["args"]]
        copy["_paths"] = [TAG.sub(_disguise, p) for p in row["_paths"]]
        copy["_dirs"] = sorted(
            {p.rsplit("/", 1)[0] for p in copy["_paths"] if "/" in p}
        )
        copy["_exts"] = sorted({_ext(p) for p in copy["_paths"]})
        copy["_argv"] = row["comm"] + "\x00" + "\x00".join(copy["args"][1:])
        out.append(copy)
    return out
