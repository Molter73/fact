#!/bin/bash
set -e

DURATION="${1:-300}"
SITE_URL="${2:-http://10.10.0.10}"
SLEEP_MIN=1
SLEEP_MAX=4

USER_AGENTS=(
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

CURL_OPTS=(-s -o /dev/null -w "%{http_code}:%{url_effective}\n" --connect-timeout 3 --max-time 10)

pick_ua() {
    echo "${USER_AGENTS[$((RANDOM % ${#USER_AGENTS[@]}))]}"
}

END=$((SECONDS + DURATION))

while [ $SECONDS -lt $END ]; do
    UA=$(pick_ua)

    case $((RANDOM % 8)) in
        0)
            curl "${CURL_OPTS[@]}" -H "User-Agent: $UA" "$SITE_URL/"
            ;;
        1)
            POST_ID=$((RANDOM % 6 + 1))
            curl "${CURL_OPTS[@]}" -H "User-Agent: $UA" \
                -H "Referer: $SITE_URL/" \
                "$SITE_URL/?p=$POST_ID"
            ;;
        2)
            TERMS=("test" "dataset" "monitoring" "analysis" "activity" "security")
            TERM="${TERMS[$((RANDOM % ${#TERMS[@]}))]}"
            curl "${CURL_OPTS[@]}" -H "User-Agent: $UA" \
                -H "Referer: $SITE_URL/" \
                "$SITE_URL/?s=$TERM"
            ;;
        3)
            PAGE_ID=$((RANDOM % 2 + 1))
            curl "${CURL_OPTS[@]}" -H "User-Agent: $UA" \
                -H "Referer: $SITE_URL/" \
                "$SITE_URL/?page_id=$PAGE_ID"
            ;;
        4)
            curl "${CURL_OPTS[@]}" -H "User-Agent: $UA" \
                -H "Referer: $SITE_URL/" \
                "$SITE_URL/feed/"
            ;;
        5)
            curl "${CURL_OPTS[@]}" -H "User-Agent: $UA" \
                -H "Referer: $SITE_URL/" \
                "$SITE_URL/wp-content/themes/twentytwentyfour/style.css"
            ;;
        6)
            POST_ID=$((RANDOM % 6 + 1))
            COMMENT_CONTENT="Interesting post! Thanks for sharing. $(date +%s)"
            curl "${CURL_OPTS[@]}" -H "User-Agent: $UA" \
                -H "Referer: $SITE_URL/?p=$POST_ID" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                -d "comment=${COMMENT_CONTENT}&author=Visitor${RANDOM}&email=user${RANDOM}@example.com&comment_post_ID=${POST_ID}&submit=Post+Comment" \
                "$SITE_URL/wp-comments-post.php"
            ;;
        7)
            curl "${CURL_OPTS[@]}" -H "User-Agent: $UA" \
                -H "Referer: $SITE_URL/" \
                "$SITE_URL/wp-json/wp/v2/posts"
            ;;
    esac

    sleep $((RANDOM % (SLEEP_MAX - SLEEP_MIN + 1) + SLEEP_MIN))
done
