#!/bin/bash
set -e

SITE_URL="${SITE_URL:-http://10.10.0.10}"
DURATION=300
CONCURRENCY=2
SSH_TARGET=""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REMOTE_DIR="/opt/dataset-traffic"

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "  Local mode (run on VM directly):"
    echo "    $0 --duration 3600 --concurrency 3"
    echo ""
    echo "  Remote mode (run from control machine):"
    echo "    $0 --duration 3600 --ssh root@10.10.0.10"
    echo ""
    echo "Options:"
    echo "  --duration SECS   Total duration in seconds (default: 300)"
    echo "  --concurrency N   Concurrent browsing sessions (default: 2)"
    echo "  --url URL         WordPress site URL (default: http://10.10.0.10)"
    echo "  --ssh HOST        SSH target for remote admin/noise execution"
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
    *) usage ;;
    esac
done

export SITE_URL

echo "=== Dataset Traffic Generator ==="
echo "Duration:    ${DURATION}s"
echo "Concurrency: ${CONCURRENCY}"
echo "Site URL:    ${SITE_URL}"
if [ -n "$SSH_TARGET" ]; then
    echo "Mode:        remote (SSH: ${SSH_TARGET})"
else
    echo "Mode:        local (run on VM)"
fi
echo ""

cleanup() {
    echo ""
    echo "Stopping traffic generation..."
    if [ -n "$SSH_TARGET" ]; then
        ssh "$SSH_TARGET" "pkill -f '/opt/dataset-traffic/' 2>/dev/null; echo done" \
            >/dev/null 2>&1 || true
    fi
    kill "${BROWSER_PIDS[@]}" 2>/dev/null || true
    wait 2>/dev/null || true
    echo "Done."
}
trap cleanup EXIT

REMOTE_ENV="SITE_URL=$SITE_URL WP_DIR=/var/www/wordpress \
MYSQL_USER=wordpress MYSQL_PASS='wp_Str0ng!Pass' MYSQL_DB=wordpress \
WP_ADMIN_USER=datasetadmin WP_ADMIN_PASS='DatasetAdmin!2024'"

launch_remote() {
    local script="$1"
    ssh -o BatchMode=yes -f "$SSH_TARGET" \
        "export $REMOTE_ENV PATH=\$PATH:/usr/local/bin; \
         nohup $REMOTE_DIR/$script $DURATION $SITE_URL > /dev/null 2>&1 &"
}

launch_local() {
    local script="$1"
    "$SCRIPT_DIR/$script" "$DURATION" "$SITE_URL" &
}

if [ -n "$SSH_TARGET" ]; then
    launch_remote "background-noise.sh"
    launch_remote "admin-workflow.sh"

    for _ in $(seq 1 "$CONCURRENCY"); do
        "$SCRIPT_DIR/web-browsing.sh" "$DURATION" "$SITE_URL" &
        BROWSER_PIDS+=($!)
    done

    echo "Workloads running remotely via ${SSH_TARGET}:"
    echo "  background-noise.sh, admin-workflow.sh"
    echo "Workloads running locally:"
    echo "  web-browsing.sh (${CONCURRENCY}x): PIDs ${BROWSER_PIDS[*]}"
    echo ""
    echo "Capturing for ${DURATION}s... (Ctrl+C to stop early)"
    echo ""

    sleep "$DURATION"
else
    launch_local "background-noise.sh"
    BG_PID=$!

    for _ in $(seq 1 "$CONCURRENCY"); do
        launch_local "web-browsing.sh"
        BROWSER_PIDS+=($!)
    done

    launch_local "admin-workflow.sh"
    ADMIN_PID=$!

    echo "Workloads running:"
    echo "  background-noise.sh: PID $BG_PID"
    echo "  web-browsing.sh (${CONCURRENCY}x): PIDs ${BROWSER_PIDS[*]}"
    echo "  admin-workflow.sh: PID $ADMIN_PID"
    echo ""
    echo "Capturing for ${DURATION}s... (Ctrl+C to stop early)"
    echo ""

    wait
fi
