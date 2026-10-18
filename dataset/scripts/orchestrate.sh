#!/bin/bash
set -e

SITE_URL="${SITE_URL:-http://10.10.0.10}"
SINK="${SINK:-10.10.0.1:4444}"
DURATION=300
CONCURRENCY=2
SSH_TARGET=""
RUN_MAINTENANCE=1
RUN_ATTACKS=0
ATTACKS_AFTER=60
ATTACKS_MANIFEST="${ATTACKS_MANIFEST:-attacks-manifest.jsonl}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REMOTE_DIR="/opt/scripts"

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "  Local mode (run on VM directly):"
    echo "    $0 --duration 3600 --concurrency 3"
    echo ""
    echo "  Remote mode (run from control machine):"
    echo "    $0 --duration 3600 --ssh vagrant@10.10.0.10"
    echo ""
    echo "Options:"
    echo "  --duration SECS   Total duration in seconds (default: 300)"
    echo "  --concurrency N   Concurrent browsing sessions (default: 2)"
    echo "  --url URL         WordPress site URL (default: http://10.10.0.10)"
    echo "  --ssh HOST        SSH target for remote admin/noise/maintenance execution"
    echo "  --no-maintenance  Skip system-maintenance.sh (it writes /etc and /usr/bin via sudo)"
    echo "  --attacks         Run attacks.sh on the monitored host"
    echo "  --attacks-after S Start the attacks S seconds in (default: 60)"
    echo "  --attacks-manifest P"
    echo "                    Attack manifest output (default: $ATTACKS_MANIFEST)"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
    --duration)
        DURATION="$2"
        shift 2
        ;;
    --concurrency)
        CONCURRENCY="$2"
        shift 2
        ;;
    --url)
        SITE_URL="$2"
        shift 2
        ;;
    --ssh)
        SSH_TARGET="$2"
        shift 2
        ;;
    --no-maintenance)
        RUN_MAINTENANCE=0
        shift
        ;;
    --attacks)
        RUN_ATTACKS=1
        shift
        ;;
    --attacks-after)
        ATTACKS_AFTER="$2"
        shift 2
        ;;
    --attacks-manifest)
        ATTACKS_MANIFEST="$2"
        shift 2
        ;;
    *) usage ;;
    esac
done

SINK_PORT="${SINK##*:}"
SINK_PID=""

MANIFEST="$ATTACKS_MANIFEST"
if [ -n "$SSH_TARGET" ]; then
    MANIFEST="/tmp/attacks-manifest.$$.jsonl"
fi
export SITE_URL SINK MANIFEST

if [ "$RUN_ATTACKS" -eq 1 ] && [ "$ATTACKS_AFTER" -ge "$DURATION" ]; then
    echo "Warning: --attacks-after ${ATTACKS_AFTER}s falls outside the ${DURATION}s capture, skipping the attacks" >&2
    RUN_ATTACKS=0
fi

echo "=== Dataset Traffic Generator ==="
echo "Duration:    ${DURATION}s"
echo "Concurrency: ${CONCURRENCY}"
echo "Site URL:    ${SITE_URL}"
if [ -n "$SSH_TARGET" ]; then
    echo "Mode:        remote (SSH: ${SSH_TARGET})"
else
    echo "Mode:        local (run on VM)"
fi

BROWSER_PIDS=()
CHILD_PIDS=()

cleanup() {
    echo ""
    echo "Stopping traffic generation..."
    if [ -n "$SSH_TARGET" ]; then
        # shellcheck disable=SC2029 # $REMOTE_DIR is expanded on purpose
        ssh "$SSH_TARGET" "pkill -f '$REMOTE_DIR/' 2>/dev/null; echo done" \
            >/dev/null 2>&1 || true
    fi
    if [ -n "$SINK_PID" ]; then
        kill "$SINK_PID" 2>/dev/null || true
        SINK_PID=""
    fi
    kill "${CHILD_PIDS[@]}" 2>/dev/null || true
    wait 2>/dev/null || true
    fetch_attacks_manifest
    echo "Done."
}
trap cleanup EXIT

REMOTE_ENV="SITE_URL=$SITE_URL WP_DIR=/usr/share/wordpress \
MYSQL_USER=wordpress MYSQL_PASS=wp_Str0ng!Pass MYSQL_DB=wordpress \
WP_ADMIN_USER=datasetadmin \
SINK=$SINK MANIFEST=$MANIFEST"

launch_remote() {
    local script="$1"
    ssh -o BatchMode=yes "$SSH_TARGET" \
        "if [ ! -x $REMOTE_DIR/$script ]; then echo 'missing $REMOTE_DIR/$script' >&2; exit 1; fi; \
         env $REMOTE_ENV setsid $REMOTE_DIR/$script $DURATION $SITE_URL \
         </dev/null >/dev/null 2>&1 &" ||
        {
            echo "Failed to launch $script on $SSH_TARGET" >&2
            return 1
        }
}

launch_local() {
    local script="$1"
    "$SCRIPT_DIR/$script" "$DURATION" "$SITE_URL" &
    CHILD_PIDS+=($!)
}

start_sink() {
    [ "$RUN_ATTACKS" -eq 1 ] || return 0

    local listener
    if command -v ncat >/dev/null 2>&1; then
        listener=ncat
    elif command -v nc >/dev/null 2>&1; then
        listener=nc
    else
        echo "No ncat or nc available: the reverse shell and exfil connects will be refused" >&2
        return 0
    fi

    "$listener" -lk "$SINK_PORT" >/dev/null 2>&1 &
    SINK_PID=$!
    sleep 1
    if kill -0 "$SINK_PID" 2>/dev/null; then
        echo "Attack sink listening on 0.0.0.0:$SINK_PORT (pid $SINK_PID)"
    else
        SINK_PID=""
        echo "Could not start the attack sink on $SINK_PORT (already in use?)" >&2
    fi
}

launch_attacks() {
    [ "$RUN_ATTACKS" -eq 1 ] || return 0

    sleep "$ATTACKS_AFTER"

    echo ""
    echo "=== attacks.sh starting ==="
    start_sink

    if [ -n "$SSH_TARGET" ]; then
        launch_remote "attacks.sh"
    else
        launch_local "attacks.sh"
    fi
}

fetch_attacks_manifest() {
    [ "$RUN_ATTACKS" -eq 1 ] || return 0
    [ -n "$SSH_TARGET" ] || return 0

    scp -q "$SSH_TARGET:$MANIFEST" "$ATTACKS_MANIFEST" || {
        echo "Could not fetch $MANIFEST from $SSH_TARGET" >&2
        return 0
    }
    echo "Attack manifest: $ATTACKS_MANIFEST"
}

if [ -n "$SSH_TARGET" ]; then
    launch_remote "background-noise.sh"
    launch_remote "admin-workflow.sh"
    if [ "$RUN_MAINTENANCE" -eq 1 ]; then
        launch_remote "system-maintenance.sh"
    fi

    for _ in $(seq 1 "$CONCURRENCY"); do
        "$SCRIPT_DIR/web-browsing.sh" "$DURATION" "$SITE_URL" &
        BROWSER_PIDS+=($!)
        CHILD_PIDS+=($!)
    done

    echo ""
    echo "Workloads running remotely via ${SSH_TARGET}:"
    echo "  background-noise.sh, admin-workflow.sh"
    [ "$RUN_MAINTENANCE" -eq 1 ] && echo "  system-maintenance.sh"
    echo "Workloads running locally:"
    echo "  web-browsing.sh (${CONCURRENCY}x): PIDs ${BROWSER_PIDS[*]}"
    echo ""
    echo "Capturing for ${DURATION}s... (Ctrl+C to stop early)"
    echo ""

    if [ "$RUN_ATTACKS" -eq 1 ]; then
        launch_attacks
        sleep $((DURATION - ATTACKS_AFTER))
    else
        sleep "$DURATION"
    fi
else
    launch_local "background-noise.sh"
    BG_PID=$!

    for _ in $(seq 1 "$CONCURRENCY"); do
        launch_local "web-browsing.sh"
        BROWSER_PIDS+=($!)
    done

    launch_local "admin-workflow.sh"
    ADMIN_PID=$!

    if [ "$RUN_MAINTENANCE" -eq 1 ]; then
        if [ "$(id -u)" -eq 0 ]; then
            launch_local "system-maintenance.sh"
            MAINT_PID=$!
        elif command -v sudo >/dev/null 2>&1; then
            sudo -n "$SCRIPT_DIR/system-maintenance.sh" "$DURATION" "$SITE_URL" &
            MAINT_PID=$!
            CHILD_PIDS+=($!)
        else
            echo "Skipping system-maintenance.sh: it writes /etc and /usr/bin and needs root or sudo."
            RUN_MAINTENANCE=0
        fi
    fi

    echo ""
    echo "Workloads running:"
    echo "  background-noise.sh: PID $BG_PID"
    echo "  web-browsing.sh (${CONCURRENCY}x): PIDs ${BROWSER_PIDS[*]}"
    echo "  admin-workflow.sh: PID $ADMIN_PID"
    [ "$RUN_MAINTENANCE" -eq 1 ] && echo "  system-maintenance.sh: PID $MAINT_PID"
    echo ""
    echo "Capturing for ${DURATION}s... (Ctrl+C to stop early)"
    echo ""

    launch_attacks

    wait "${CHILD_PIDS[@]}" 2>/dev/null || true
fi
