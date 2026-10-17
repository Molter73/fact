#!/bin/bash
set -e

DURATION="${1:-3600}"
WP_DIR="${WP_DIR:-/usr/share/wordpress}"
MYSQL_USER="${MYSQL_USER:-wordpress}"
MYSQL_PASS="${MYSQL_PASS:-wp_Str0ng!Pass}"
MYSQL_DB="${MYSQL_DB:-wordpress}"

end=$((SECONDS + DURATION))

while [ $SECONDS -lt $end ]; do
    case $((RANDOM % 12)) in
    0)
        find "$WP_DIR" -name "*.php" -type f | wc -l >/dev/null
        ;;
    1)
        du -sh "$WP_DIR" >/dev/null
        ;;
    2)
        tail -n 10 /var/log/nginx/access.log 2>/dev/null || true
        ;;
    3)
        mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" "$MYSQL_DB" \
            -N -B -e "SELECT COUNT(*) FROM wp_posts;" 2>/dev/null || true
        ;;
    4)
        redis-cli PING 2>/dev/null || true
        ;;
    5)
        ps aux --sort=-%cpu | head -20 >/dev/null
        ;;
    6)
        stat "$WP_DIR/wp-config.php" >/dev/null 2>&1 || true
        ;;
    7)
        df -h / >/dev/null
        ;;
    8)
        journalctl -n 50 --no-pager >/dev/null 2>&1 || true
        ;;
    9)
        systemctl is-active nginx mariadb php-fpm redis >/dev/null 2>&1 || true
        ;;
    10)
        # Nightly housekeeping: the logrotate timer firing.
        command -v logrotate >/dev/null 2>&1 || true
        logrotate -f /etc/logrotate.conf >/dev/null 2>&1 || true
        ;;
    11)
        ss -s >/dev/null 2>&1 || true
        rpm -qa | wc -l >/dev/null 2>&1 || true
        ;;
    esac

    sleep $((RANDOM % 3 + 1))
done
