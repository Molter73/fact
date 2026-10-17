#!/bin/bash
set -e

DURATION="${1:-3600}"
MYSQL_USER="${MYSQL_USER:-wordpress}"
MYSQL_PASS="${MYSQL_PASS:-wp_Str0ng!Pass}"
MYSQL_DB="${MYSQL_DB:-wordpress}"

WP_DIR="${WP_DIR:-/usr/share/wordpress}"

PKG_POOL=(tree jq unzip rsync htop)

PKG_MIN_AGE="${PKG_MIN_AGE:-600}"

FIREWALL_SERVICES=(mysql postgresql samba cockpit)

UNIT_NAME="ds-maintenance"
SYSCTL_FILE="/etc/sysctl.d/99-ds-tuning.conf"
CRON_FILE="/etc/cron.d/ds-report"

INSTALLED_USERS=()
ADDED_SERVICES=()

declare -A PKG_SINCE=()
declare -A PKG_ORDER=()
PKG_SEQ=0

SUDO=""
[ "$(id -u)" -ne 0 ] && SUDO="sudo"

install_pkg() {
    local pkg="$1"
    rpm -q "$pkg" >/dev/null 2>&1 && return 0
    $SUDO dnf install -y "$pkg" >/dev/null 2>&1 || return 0
    PKG_SEQ=$((PKG_SEQ + 1))
    PKG_SINCE["$pkg"]=$EPOCHSECONDS
    PKG_ORDER["$pkg"]=$PKG_SEQ
}

forget_pkg() {
    unset 'PKG_SINCE[$1]' 'PKG_ORDER[$1]'
}

provision_tools() {
    local pkg
    for pkg in "${PKG_POOL[@]}"; do
        install_pkg "$pkg"
    done
}

pkg_retire() {
    [ ${#PKG_SINCE[@]} -gt 0 ] || return 0

    local oldest="" oldest_order="" pkg
    for pkg in "${PKG_POOL[@]}"; do
        [ -n "${PKG_SINCE[$pkg]:-}" ] || continue
        [ $((EPOCHSECONDS - PKG_SINCE[$pkg])) -ge "$PKG_MIN_AGE" ] || continue
        if [ -z "$oldest" ] || [ "${PKG_ORDER[$pkg]}" -lt "$oldest_order" ]; then
            oldest="$pkg"
            oldest_order="${PKG_ORDER[$pkg]}"
        fi
    done

    [ -n "$oldest" ] || return 0

    $SUDO dnf remove -y "$oldest" >/dev/null 2>&1 || return 0
    forget_pkg "$oldest"
}

pkg_restore() {
    local pkg
    for pkg in "${PKG_POOL[@]}"; do
        if [ -z "${PKG_SINCE[$pkg]:-}" ]; then
            install_pkg "$pkg"
            return 0
        fi
    done
}

cleanup() {
    trap - EXIT INT TERM

    $SUDO systemctl disable --now "$UNIT_NAME.timer" >/dev/null 2>&1 || true
    $SUDO rm -f "/etc/systemd/system/$UNIT_NAME.timer" \
        "/etc/systemd/system/$UNIT_NAME.service" 2>/dev/null || true
    $SUDO systemctl daemon-reload >/dev/null 2>&1 || true

    $SUDO rm -f "$CRON_FILE" "$SYSCTL_FILE" 2>/dev/null || true

    for user in "${INSTALLED_USERS[@]:-}"; do
        [ -n "$user" ] && $SUDO userdel "$user" >/dev/null 2>&1 || true
    done

    for service in "${ADDED_SERVICES[@]:-}"; do
        [ -n "$service" ] && $SUDO firewall-cmd --permanent --remove-service="$service" >/dev/null 2>&1 || true
    done
    command -v firewall-cmd >/dev/null 2>&1 && $SUDO firewall-cmd --reload >/dev/null 2>&1 || true

    for pkg in "${!PKG_SINCE[@]}"; do
        $SUDO dnf remove -y "$pkg" >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

timer_deploy() {
    if [ -f "/etc/systemd/system/$UNIT_NAME.timer" ]; then
        $SUDO systemctl disable --now "$UNIT_NAME.timer" >/dev/null 2>&1 || true
        $SUDO rm -f "/etc/systemd/system/$UNIT_NAME.timer" \
            "/etc/systemd/system/$UNIT_NAME.service" 2>/dev/null || true
        $SUDO systemctl daemon-reload >/dev/null 2>&1 || true
        return 0
    fi

    $SUDO tee "/etc/systemd/system/$UNIT_NAME.service" >/dev/null <<EOF
[Unit]
Description=WordPress housekeeping pass
After=mariadb.service

[Service]
Type=oneshot
ExecStart=/usr/bin/wp option get siteurl --path=$WP_DIR
EOF

    $SUDO tee "/etc/systemd/system/$UNIT_NAME.timer" >/dev/null <<EOF
[Unit]
Description=Run the WordPress housekeeping pass every 5 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min
Persistent=true

[Install]
WantedBy=timers.target
EOF

    $SUDO chmod 0644 "/etc/systemd/system/$UNIT_NAME.service" \
        "/etc/systemd/system/$UNIT_NAME.timer" 2>/dev/null || true
    $SUDO chown root:root "/etc/systemd/system/$UNIT_NAME.service" \
        "/etc/systemd/system/$UNIT_NAME.timer" 2>/dev/null || true

    $SUDO systemctl daemon-reload >/dev/null 2>&1 || true
    $SUDO systemctl enable --now "$UNIT_NAME.timer" >/dev/null 2>&1 || true
}

service_account() {
    if [ ${#INSTALLED_USERS[@]} -gt 0 ]; then
        local user="${INSTALLED_USERS[RANDOM % ${#INSTALLED_USERS[@]}]}"
        local remaining=()
        for installed in "${INSTALLED_USERS[@]}"; do
            if [ "$installed" != "$user" ]; then
                remaining+=("$installed")
            fi
        done
        INSTALLED_USERS=("${remaining[@]}")
        $SUDO userdel "$user" >/dev/null 2>&1 || true
        return 0
    fi

    local user="ds-svc-$((RANDOM % 100 + 10))"
    $SUDO useradd -r -M -s /sbin/nologin -c "Dataset service account" "$user" >/dev/null 2>&1 || return 0
    INSTALLED_USERS+=("$user")
}

firewall_rule() {
    command -v firewall-cmd >/dev/null 2>&1 || return 0

    if [ ${#ADDED_SERVICES[@]} -gt 0 ]; then
        local service="${ADDED_SERVICES[RANDOM % ${#ADDED_SERVICES[@]}]}"
        local remaining=()
        for added in "${ADDED_SERVICES[@]}"; do
            if [ "$added" != "$service" ]; then
                remaining+=("$added")
            fi
        done
        ADDED_SERVICES=("${remaining[@]}")
        $SUDO firewall-cmd --permanent --remove-service="$service" >/dev/null 2>&1 || true
        $SUDO firewall-cmd --reload >/dev/null 2>&1 || true
        return 0
    fi

    local service="${FIREWALL_SERVICES[RANDOM % ${#FIREWALL_SERVICES[@]}]}"
    $SUDO firewall-cmd --permanent --add-service="$service" >/dev/null 2>&1 || return 0
    $SUDO firewall-cmd --reload >/dev/null 2>&1 || true
    ADDED_SERVICES+=("$service")
}

sysctl_tuning() {
    if [ -f "$SYSCTL_FILE" ]; then
        $SUDO rm -f "$SYSCTL_FILE" 2>/dev/null || true
        return 0
    fi

    $SUDO tee "$SYSCTL_FILE" >/dev/null <<EOF
# dataset tuning, $(date '+%Y-%m-%d')
net.ipv4.tcp_syncookies = 1
kernel.randomize_va_space = 2
fs.suid_dumpable = 1
EOF
    $SUDO chmod 0644 "$SYSCTL_FILE" 2>/dev/null || true
    $SUDO sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true
}

db_maintenance() {
    local table=("wp_posts" "wp_comments" "wp_options" "wp_postmeta")

    if command -v mysqlcheck >/dev/null 2>&1; then
        mysqlcheck -u "$MYSQL_USER" -p"$MYSQL_PASS" --optimize \
            "$MYSQL_DB" "${table[RANDOM % ${#table[@]}]}" >/dev/null 2>&1 || true
    elif command -v mariadb-check >/dev/null 2>&1; then
        mariadb-check -u "$MYSQL_USER" -p"$MYSQL_PASS" --optimize \
            "$MYSQL_DB" "${table[RANDOM % ${#table[@]}]}" >/dev/null 2>&1 || true
    fi
}

provision_tools

end=$((SECONDS + DURATION))

while [ $SECONDS -lt $end ]; do
    case $((RANDOM % 7)) in
    0)
        db_maintenance
        ;;
    1)
        pkg_retire
        ;;
    2)
        pkg_restore
        ;;
    3)
        timer_deploy
        ;;
    4)
        sysctl_tuning
        ;;
    5)
        service_account
        ;;
    6)
        firewall_rule
        ;;
    esac

    sleep $((RANDOM % 60 + 30)) &
    wait $! 2>/dev/null || true
done
