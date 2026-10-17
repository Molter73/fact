#!/bin/bash
set -e

DURATION="${1:-3600}"
WP_DIR="${WP_DIR:-/usr/share/wordpress}"
WP_ADMIN_USER="${WP_ADMIN_USER:-datasetadmin}"
WP_ADMIN_PASS="${WP_ADMIN_PASS:-DatasetAdmin!2024}"

end=$((SECONDS + DURATION))

while [ $SECONDS -lt $end ]; do
    POST_ID=$(wp post create \
        --post_title="Auto-generated $(date '+%Y-%m-%d %H:%M:%S')" \
        --post_content="Automatically generated for dataset traffic. Uptime: $(uptime -p)" \
        --post_status=publish \
        --porcelain \
        --path="$WP_DIR" \
        --user="$WP_ADMIN_USER" \
        2>/dev/null) || {
        sleep 60
        continue
    }

    CATEGORY=$((RANDOM % 3 + 1))
    wp post term add "$POST_ID" category "$CATEGORY" --path="$WP_DIR" 2>/dev/null || true

    TAG_CHOICES=("dataset" "monitoring" "analysis" "system-activity" "research")
    TAG="${TAG_CHOICES[$((RANDOM % ${#TAG_CHOICES[@]}))]}"
    wp post term add "$POST_ID" post_tag "$TAG" --path="$WP_DIR" 2>/dev/null || true

    IMG=$(mktemp /tmp/dataset-img-XXXXXX.png)
    printf '%s' 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==' |
        base64 -d >"$IMG" 2>/dev/null

    wp media import "$IMG" --post_id="$POST_ID" \
        --path="$WP_DIR" --user="$WP_ADMIN_USER" 2>/dev/null || true
    rm -f "$IMG"

    INTERVAL=$((RANDOM % 60 + 30))
    sleep $INTERVAL
done
