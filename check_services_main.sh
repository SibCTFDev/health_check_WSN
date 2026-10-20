#!/bin/sh

set -u

SERVER=${1:-sectasks.yc.ftc.ru}
TIMEOUT=${CURL_TIMEOUT:-5}
CHECK_LLM=${CHECK_LLM:-0}
failed=0

printf 'Checking CTF services on %s\n\n' "$SERVER"
printf '%-8s %-32s %-24s %s\n' PORT SERVICE PATH STATUS

check_http() {
    port=$1
    service=$2
    path=$3
    result=$(curl -sS -o /dev/null -w '%{http_code}\t%{time_total}' \
        --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" \
        "http://$SERVER:$port$path" 2>/dev/null)
    rc=$?
    code=$(printf '%s' "$result" | cut -f1)
    elapsed=$(printf '%s' "$result" | cut -f2)

    if [ "$rc" -eq 0 ] && [ "$code" != 000 ]; then
        printf '%-8s %-32s %-24s UP (HTTP %s, %ss)\n' \
            "$port" "$service" "$path" "$code" "$elapsed"
    else
        printf '%-8s %-32s %-24s DOWN (%s)\n' \
            "$port" "$service" "$path" "${code:-curl $rc}"
        failed=$((failed + 1))
    fi
}

check_tcp() {
    port=$1
    service=$2
    path=$3
    trace=$(curl -sS -v -o /dev/null \
        --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" \
        "telnet://$SERVER:$port" </dev/null 2>&1)

    if printf '%s\n' "$trace" | grep -q 'Connected to'; then
        printf '%-8s %-32s %-24s UP (TCP)\n' "$port" "$service" "$path"
    else
        printf '%-8s %-32s %-24s DOWN (TCP)\n' "$port" "$service" "$path"
        failed=$((failed + 1))
    fi
}

# Порты и пути соответствуют опубликованным маршрутам CTF_Tasks_WEBSN.
while IFS='|' read -r port service path kind; do
    case "$kind" in
        http) check_http "$port" "$service" "$path" ;;
        tcp)  check_tcp  "$port" "$service" "$path" ;;
        llm)  [ "$CHECK_LLM" = "1" ] && check_http "$port" "$service" "$path" ;;
    esac
done <<'SERVICES'
5010|BrokenAccess Super_file|/|http
6633|BrokenAccess Header|/check-header|http
5011|BrokenAccess miniExpress|/|http
8082|BrokenAccess Auction|/api/user/4|http
6676|BrokenAccess Claims|/|http
6677|BrokenAccess Legacy|/|http
8031|XXE xxe1|/xml|http
8032|XXE xxe2|/xml|http
8033|XXE file upload|/|http
5001|SQLi API Kvarplata|/static/swagger.json|http
5002|SQLi Login DP|/|http
5003|SQLi Oy My Hesh|/|http
5004|SQLi Super SQLi|/|http
8007|Vulnerabilities Apache|/|http
8081|Vulnerabilities Lib TCP|tcp|tcp
8091|Vulnerabilities Lib HTTP|/whats_time|http
5069|Vulnerabilities Keys Hash|/|http
5041|Client Hashcat JWT|/|http
5042|Client JWT ANSEC|/|http
5043|Client JWToken|/login|http
5044|Client NuLia|/|http
5045|Client XSS|/|http
5046|Client CSRF|/|http
5047|Client Catch Me|/|http
3000|Client XSS ticket|/|http
25000|Secure bank exploit|/|http
25001|Secure bank vuln app|/|http
25002|Secure bank bot|/stats|http
33300|Client-side portal|/|http
33301|Client-side Customer|/|http
33302|Client-side Username Generator|/|http
33303|Client-side Pasteurize|/|http
33304|Client-side Cookie World Order|/|http
33305|Client-side Babier CSP|/|http
33390|Username Generator admin bot|/|http
33399|Client-side admin bot|/|http
5088|Crypto JWT|/|http
8001|LeakBox level 1|/health|llm
8002|LeakBox level 2|/health|llm
8003|LeakBox level 3|/health|llm
SERVICES

printf '\nResult: %s\n' "$([ "$failed" -eq 0 ] && printf 'all services are reachable' || printf '%s service(s) failed' "$failed")"
exit "$([ "$failed" -eq 0 ] && printf 0 || printf 1)"
