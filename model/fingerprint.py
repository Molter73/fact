"""Fingerprint and basename templates used to collapse repeated alerts."""

import hashlib
import re

STRATEGIES = ("comm", "comm_parent", "comm_parent_path", "comm_parent_argv")
DEFAULT = "comm_parent_argv"

TAG = re.compile(r"atk-[a-z_0-9]+-\d+-\d+")
UUID = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE
)
HEX = re.compile(r"\b[0-9a-f]{6,}\b", re.IGNORECASE)
LONG_NUM = re.compile(r"\b\d{8,}\b")
INODE_SUFFIX = re.compile(r";[0-9a-f]{6,}$", re.IGNORECASE)
EXT = re.compile(r"(\.[A-Za-z0-9]{1,8})$")
DATE_YEAR = re.compile(r"^(?:19|20)\d{2}$")
DATE_MONTH = re.compile(r"^(?:0[1-9]|1[0-2])$")
TEMP_SUFFIX = re.compile(
    r"([._-])(?=[A-Za-z0-9]{6,}$)(?=[A-Za-z0-9]*[A-Za-z])(?=[A-Za-z0-9]*[0-9])"
    r"[A-Za-z0-9]*$"
)


def _text(value):
    value = TAG.sub("<tag>", value)
    value = UUID.sub("<uuid>", value)
    value = TEMP_SUFFIX.sub(r"\1<tmp>", value)
    value = LONG_NUM.sub("<n>", value)
    value = HEX.sub("<hex>", value)
    return value


def component_pattern(component):
    component = INODE_SUFFIX.sub("", component)
    return re.sub(r"\d+", "<n>", _text(component))


def _path_components(path):
    out = []
    previous = None
    for component in path.split("/"):
        if DATE_YEAR.fullmatch(component):
            value = "<year>"
        elif DATE_MONTH.fullmatch(component) and previous == "<year>":
            value = "<month>"
        else:
            value = component_pattern(component)
        out.append(value)
        previous = value
    return out


def basename_pattern(path):
    if not path:
        return ""
    path = INODE_SUFFIX.sub("", path.rstrip("/"))
    base = TEMP_SUFFIX.sub(r"\1<tmp>", path.rsplit("/", 1)[-1])
    match = EXT.search(base)
    ext = match.group(1).lower() if match else ""
    stem = base[: -len(ext)] if ext else base
    stem = re.sub(r"\d+", "<n>", _text(stem))
    return f"{stem}{ext}"


def path_template(path):
    if not path:
        return ""
    path = INODE_SUFFIX.sub("", path)
    if "/" not in path:
        return basename_pattern(path)
    directory, base = path.rsplit("/", 1)
    base = TEMP_SUFFIX.sub(r"\1<tmp>", base)
    match = EXT.search(base)
    ext = match.group(1).lower() if match else ""
    directory = "/".join(_path_components(directory))
    return f"{directory}/<name>{ext}"


def _argv_token(token):
    if token.startswith("-") and "=" in token:
        return token.split("=", 1)[0] + "=<value>"
    if "/" in token:
        return path_template(token)
    return re.sub(r"\d+", "<n>", _text(token))


def argv_template(row):
    return "\x00".join(
        [
            _text(row.get("comm", "")),
            *(_argv_token(arg) for arg in row.get("args", [])[1:]),
        ]
    )


def _digest(value):
    return hashlib.sha1(value.encode("utf-8", "surrogateescape")).hexdigest()[:12]


def fingerprint(row, strategy=DEFAULT):
    if strategy not in STRATEGIES:
        raise ValueError(f"unknown fingerprint strategy: {strategy}")
    comm = row.get("comm", "")
    parent = row.get("parent_comm", "")
    if strategy == "comm":
        return comm
    if strategy == "comm_parent":
        return f"{comm}\x1f{parent}"
    if strategy == "comm_parent_path":
        templates = "\x00".join(
            sorted({path_template(p) for p in row.get("_paths", [])})
        )
        return f"{comm}\x1f{parent}\x1f{_digest(templates)}"
    return f"{comm}\x1f{parent}\x1f{_digest(argv_template(row))}"


def describe(row, strategy=DEFAULT):
    paths = sorted({basename_pattern(p) for p in row.get("_paths", []) if p})
    return {
        "fingerprint": fingerprint(row, strategy),
        "basename_pattern": paths[0]
        if paths
        else basename_pattern(row.get("exe_path", "")),
    }
