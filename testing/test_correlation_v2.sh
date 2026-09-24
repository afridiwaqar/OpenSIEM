#!/usr/bin/env bash
# =============================================================================
# OpenSIEM Correlation Engine v2 — Test Script
#
# Seeds specific test use-cases, sends crafted log lines via TCP to the
# OpenSIEM ingestion port, then checks the alerts table to verify each rule
# fired correctly.
#
# Usage:
#   chmod +x test_correlation_v2.sh
#   ./test_correlation_v2.sh [server_ip] [port]
#
# Defaults: server_ip=127.0.0.1  port=11514
#
# What is tested:
#   Test 1 — Basic sequence rule (SSH brute force)
#   Test 2 — Time-window enforcement (steps too far apart — should NOT fire)
#   Test 3 — Sequence ordering enforcement (steps in wrong order — should NOT fire)
#   Test 4 — User-based entity grouping (same user, different IPs)
#   Test 5 — Cooldown enforcement (rule should fire once, not twice)
#   Test 6 — Threshold-based rule (N events in M seconds)
#   Test 7 — Global / multi-IP distributed detection
# =============================================================================

set -euo pipefail

SERVER_IP="${1:-127.0.0.1}"
SERVER_PORT="${2:-11514}"
DB_NAME="${DB_NAME:-museum}"
DB_USER="${DB_USER:-opensiem}"
CERT_PATH="${CERT_PATH:-/etc/opensiem/certs/server.crt}"

PSQL="psql -U $DB_USER -d $DB_NAME -v ON_ERROR_STOP=1 -t -A"

GRN='\033[0;32m'; RED='\033[0;31m'; YLW='\033[1;33m'; BLU='\033[0;34m'; NC='\033[0m'

# Auto-detect TLS mode — try a plaintext probe, if rejected assume TLS required
# TLS_MODE="false"
# if printf '\n' | nc -q1 -w2 "$SERVER_IP" "$SERVER_PORT" 2>/dev/null; then
#     echo "Mode: plaintext"
# else
#     if [[ -f "$CERT_PATH" ]]; then
#         TLS_MODE="true"
#         echo "Mode: TLS (cert found at $CERT_PATH)"
#     else
#         echo "Mode: TLS required but cert not found at $CERT_PATH — tests may fail"
#         TLS_MODE="true"
#     fi
# fi

# FIX: Test TLS connection directly using openssl instead of plaintext nc probe
TLS_MODE="false"
if openssl s_client -connect "${SERVER_IP}:${SERVER_PORT}" -CAfile "$CERT_PATH" </dev/null 2>/dev/null | grep -q "Verify return code"; then
    TLS_MODE="true"
    echo "Mode: TLS (verified via cert at $CERT_PATH)"

elif [[ -f "$CERT_PATH" ]]; then
    # Fallback if server is running TLS
    TLS_MODE="true"
    echo "Mode: TLS (forced via cert presence at $CERT_PATH)"
    echo "Using TLS Mode.........................................."
else
    echo "Mode: Plaintext"
fi

pass=0; fail=0; total=0

_pass() { echo -e "  ${GRN}✓ PASS${NC}: $1"; ((pass++)); ((total++)); }
_fail() { echo -e "  ${RED}✗ FAIL${NC}: $1"; ((fail++)); ((total++)); }
_info() { echo -e "  ${BLU}ℹ${NC}  $1"; }
_head() { echo -e "\n${YLW}══ $1 ══${NC}"; }

# =============================================================================
# Helpers
# =============================================================================

# send_log() {
#     local src_ip="$1"
#     local parser="$2"
#     local message="$3"
#     local ts
#     ts=$(date "+%b %e %H:%M:%S")
#     local syslog_line="${ts} testhost opensiem[1]: ${message}"
#     local wire="${src_ip} ${parser} ${syslog_line}"

#     if [[ "$TLS_MODE" == "true" ]]; then
#         printf '%s\n' "$wire" | \
#             openssl s_client -connect "${SERVER_IP}:${SERVER_PORT}" \
#             -CAfile "$CERT_PATH" -quiet -ign_eof 2>/dev/null || true
#     else
#         printf '%s\n' "$wire" | \
#             nc -q1 "$SERVER_IP" "$SERVER_PORT" 2>/dev/null || true
#     fi
#     sleep 0.2
# }

send_log() {
    local src_ip="$1"
    local parser="$2"
    local message="$3"
    local ts
    # Force English month names (e.g. "Sep" instead of "ستمبر")
    ts=$(LC_ALL=C date "+%b %e %H:%M:%S")
    local syslog_line="${ts} testhost opensiem[1]: ${message}"
    local wire="${src_ip} ${parser} ${syslog_line}"

    if [[ "$TLS_MODE" == "true" ]]; then
        # Wrap openssl with 'timeout 2' to send data and terminate cleanly
        echo "Sending Logs using TLS.........................................."
        printf '%s\n' "$wire" | \
            timeout 2 openssl s_client -connect "${SERVER_IP}:${SERVER_PORT}" \
            -CAfile "$CERT_PATH" -quiet 2>/dev/null || true
    else
        printf '%s\n' "$wire" | \
            nc -q1 "$SERVER_IP" "$SERVER_PORT" 2>/dev/null || true
        
        echo "Sending Logs using Plain.........................................."
    fi
    sleep 0.2
}

# Capture the current max alert ID before tests start
# so we only look at alerts created DURING this test run
TEST_START_ALERT_ID=0

init_alert_watermark() {
    TEST_START_ALERT_ID=$($PSQL -c "SELECT COALESCE(MAX(id), 0) FROM alerts" 2>/dev/null || echo 0)
    _info "Alert watermark set at id > $TEST_START_ALERT_ID"
}

alert_count() {
    local case_name="$1"
    # Count alerts created after our watermark matching the case name
    $PSQL -c "
        SELECT COUNT(*) FROM alerts
        WHERE admin_note LIKE '%${case_name}%'
          AND id > ${TEST_START_ALERT_ID}
    " 2>/dev/null || echo 0
}

wait_for_alert() {
    local case_name="$1"
    local max_wait="${2:-15}"
    local elapsed=0
    while [ $elapsed -lt $max_wait ]; do
        cnt=$(alert_count "$case_name")
        if [ "$cnt" -gt 0 ]; then echo ""; return 0; fi
        sleep 1; ((elapsed++))
        echo -n "."
    done
    echo ""
    return 1
}

# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================

_head "PRE-FLIGHT CHECKS"

# 1. Check which correlation.py is running
echo -e "\n${BLU}[1] Correlation engine version:${NC}"
if grep -q "CHECKing Correlation" /opt/opensiem/correlation.py 2>/dev/null; then
    echo -e "  ${RED}✗ OLD correlation.py is deployed — new engine not active${NC}"
    echo -e "    Fix: copy the new correlation.py to /opt/opensiem/ and restart"
    PREFLIGHT_OK=false
elif grep -q "GLOBAL_KEY\|time_window_seconds\|cooldown_tracker" /opt/opensiem/correlation.py 2>/dev/null; then
    echo -e "  ${GRN}✓ New correlation.py (v2) is deployed${NC}"
else
    echo -e "  ${YLW}? Cannot determine correlation.py version${NC}"
fi

# 2. Check reload port
echo -e "\n${BLU}[2] Correlation admin server (port 51808):${NC}"
RELOAD_RESP=$(curl -s -X POST http://127.0.0.1:51808/reload 2>/dev/null)
if echo "$RELOAD_RESP" | grep -q '"ok": true'; then
    UC=$(echo "$RELOAD_RESP" | grep -oP '"use_cases": \K[0-9]+')
    PT=$(echo "$RELOAD_RESP" | grep -oP '"patterns": \K[0-9]+')
    echo -e "  ${GRN}✓ Admin server responding — use_cases=$UC patterns=$PT${NC}"
    if [ "${UC:-0}" -lt 1 ]; then
        echo -e "  ${RED}✗ No use_cases loaded — DB seed may have failed${NC}"
    fi
else
    echo -e "  ${RED}✗ Admin server not responding — correlation._start_admin_server() not called${NC}"
    echo -e "    Fix: ensure correlation._start_admin_server() is in opensiem.py main block"
fi

# 3. Check test patterns are in DB
echo -e "\n${BLU}[3] Test patterns in database:${NC}"
PATTERN_COUNT=$($PSQL -c "SELECT COUNT(*) FROM special_messages WHERE msg_id BETWEEN 9000 AND 9099" 2>/dev/null || echo 0)
if [ "${PATTERN_COUNT:-0}" -ge 13 ]; then
    echo -e "  ${GRN}✓ $PATTERN_COUNT test patterns found in special_messages${NC}"
else
    echo -e "  ${RED}✗ Only $PATTERN_COUNT test patterns found (expected 13)${NC}"
fi

# 4. Test that a log actually reaches the engine
echo -e "\n${BLU}[4] Log delivery test (send one log, check it appears in server log):${NC}"
BEFORE=$(journalctl -u opensiem.service --since "now" 2>/dev/null | wc -l || echo 0)
send_log "10.99.0.1" "modules/parse_syslog.py" "preflight_test_marker_xyz"
sleep 1
AFTER_LOG=$(journalctl -u opensiem.service -n 20 --no-pager 2>/dev/null | grep -c "preflight_test_marker\|Log message.*preflight" || echo 0)
if [ "${AFTER_LOG:-0}" -gt 0 ]; then
    echo -e "  ${GRN}✓ Log reached and was processed by the server${NC}"
else
    echo -e "  ${YLW}? Log sent but not visible in server log — may still be processing${NC}"
    echo -e "    (This is OK if TLS mode is working — check journalctl manually)"
fi

# 5. Test pattern matching directly
echo -e "\n${BLU}[5] Pattern matching test (Python inline):${NC}"
MATCH_RESULT=$(python3 -c "
import sys
sys.path.insert(0, '/opt/opensiem')
try:
    import correlation
    # Simulate what parse_syslog produces for our test message
    log_obj = {'message': 'test_login_failed event', 'format': 'FALLBACK', 'process': 'opensiem'}
    matches = correlation.check_message_match(log_obj, '10.99.1.1')
    if matches:
        print('MATCH:' + str(len(matches)))
    else:
        # Try with message text containing the pattern
        log_obj2 = {'message': 'opensiem[1]: test_login_failed event'}
        matches2 = correlation.check_message_match(log_obj2, '10.99.1.1')
        if matches2:
            print('MATCH_V2:' + str(len(matches2)))
        else:
            print('NO_MATCH')
except Exception as e:
    print('ERROR:' + str(e))
" 2>/dev/null)

if echo "$MATCH_RESULT" | grep -q "^MATCH"; then
    echo -e "  ${GRN}✓ Pattern matching works — $MATCH_RESULT${NC}"
elif echo "$MATCH_RESULT" | grep -q "^ERROR"; then
    echo -e "  ${RED}✗ Error in correlation engine: ${MATCH_RESULT}${NC}"
else
    echo -e "  ${RED}✗ Pattern NOT matching — test_login_failed not found in log text${NC}"
    echo -e "    Diagnosing what parse_syslog returns for our test format..."
    python3 -c "
import sys
sys.path.insert(0, '/opt/opensiem')
from modules import parse_syslog
import datetime
ts = datetime.datetime.now().strftime('%b %e %H:%M:%S')
raw = f'$ts testhost opensiem[1]: test_login_failed event'
result = parse_syslog.parse_log(raw)
print(f'    parse_syslog output: {result}')
from correlation import _to_msg_text, _normalize
if result:
    text = _to_msg_text(result)
    print(f'    _to_msg_text: {repr(text)}')
    print(f'    _normalize:   {repr(_normalize(text))}')
    print(f'    Contains test_login_failed: {\"test_login_failed\" in _normalize(text)}')
" 2>/dev/null
fi

echo -e "\n${YLW}Pre-flight complete. Starting tests...${NC}\n"

# =============================================================================
# Setup — insert test use-cases
# =============================================================================

_head "SETUP — Seeding test use-cases"

$PSQL << 'SQL'
BEGIN;

-- Remove any leftover test data from previous runs
DELETE FROM special_messages WHERE msg_id BETWEEN 9000 AND 9099;
DELETE FROM use_cases       WHERE case_id BETWEEN 900 AND 909;

-- Test 1: Basic sequence — LOGIN_FAILED then LOGIN_SUCCESS (5-min window)
INSERT INTO use_cases (case_id, case_name, entity_field, severity, time_window_seconds, cooldown_seconds)
VALUES (900, 'TEST_Basic_Sequence', 'ip', 'high', 300, 10)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, time_window_seconds=EXCLUDED.time_window_seconds,
    cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(9000, 900, 'test_login_failed',  true,  1),
(9001, 900, 'test_login_success', false, 2)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


-- Test 2: Time-window — same sequence but 5-second window (will expire before 2nd step sent)
INSERT INTO use_cases (case_id, case_name, entity_field, severity, time_window_seconds, cooldown_seconds)
VALUES (901, 'TEST_Window_Expired', 'ip', 'high', 5, 10)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, time_window_seconds=EXCLUDED.time_window_seconds,
    cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(9010, 901, 'test_window_step_one', false, 1),
(9011, 901, 'test_window_step_two', false, 2)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


-- Test 3: Sequence ordering — steps must arrive in order
INSERT INTO use_cases (case_id, case_name, entity_field, severity, time_window_seconds, cooldown_seconds)
VALUES (902, 'TEST_Order_Enforced', 'ip', 'high', 300, 10)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, time_window_seconds=EXCLUDED.time_window_seconds,
    cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(9020, 902, 'test_order_first',  false, 1),
(9021, 902, 'test_order_second', false, 2)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


-- Test 4: User-based grouping — same user, different IPs
INSERT INTO use_cases (case_id, case_name, entity_field, severity, time_window_seconds, cooldown_seconds)
VALUES (903, 'TEST_User_Grouping', 'user', 'high', 300, 10)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, entity_field=EXCLUDED.entity_field,
    time_window_seconds=EXCLUDED.time_window_seconds, cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(9030, 903, 'test_user_fail',    false, 0),
(9031, 903, 'test_user_success', false, 0)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


-- Test 5: Cooldown — rule fires once, second trigger within cooldown ignored
INSERT INTO use_cases (case_id, case_name, entity_field, severity, time_window_seconds, cooldown_seconds)
VALUES (904, 'TEST_Cooldown', 'ip', 'high', 300, 60)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, time_window_seconds=EXCLUDED.time_window_seconds,
    cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(9040, 904, 'test_cooldown_step_a', false, 0),
(9041, 904, 'test_cooldown_step_b', false, 0)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


-- Test 6: Threshold-based rule — 5 events in 30 seconds
INSERT INTO use_cases (case_id, case_name, entity_field, severity,
                       time_window_seconds, cooldown_seconds,
                       threshold_count, threshold_window_seconds)
VALUES (905, 'TEST_Threshold', 'ip', 'high', 300, 10, 5, 30)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, threshold_count=EXCLUDED.threshold_count,
    threshold_window_seconds=EXCLUDED.threshold_window_seconds,
    cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(9050, 905, 'test_threshold_event', true, 0)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


-- Test 7: Global / multi-IP distributed detection
INSERT INTO use_cases (case_id, case_name, entity_field, severity, time_window_seconds, cooldown_seconds)
VALUES (906, 'TEST_Distributed', 'global', 'high', 300, 10)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, entity_field=EXCLUDED.entity_field,
    time_window_seconds=EXCLUDED.time_window_seconds, cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(9060, 906, 'test_distributed_from_bot', true, 0),
(9061, 906, 'test_distributed_target',   true, 0)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


COMMIT;
SQL

echo -e "${GRN}Test use-cases seeded.${NC}"

# Reload correlation engine
echo -e "\nReloading correlation engine..."
RELOAD=$(curl -s -X POST http://127.0.0.1:51808/reload 2>/dev/null || echo '{}')
echo "Reload response: $RELOAD"
sleep 2

# Verify the engine actually loaded the test cases
UC_COUNT=$(echo "$RELOAD" | grep -oP '"use_cases":\s*\K[0-9]+' || echo 0)
if [ "${UC_COUNT:-0}" -lt 7 ]; then
    echo -e "${RED}ERROR: Engine only loaded $UC_COUNT use_cases — expected 7+${NC}"
    echo "Forcing second reload..."
    sleep 2
    RELOAD=$(curl -s -X POST http://127.0.0.1:51808/reload 2>/dev/null || echo '{}')
    echo "Second reload: $RELOAD"
    sleep 2
fi

PARSER="modules/parse_syslog.py"

# Set alert watermark so we only detect alerts raised during THIS run
init_alert_watermark

# =============================================================================
# TEST 1 — Basic sequence rule
# =============================================================================
_head "TEST 1: Basic sequence rule (should FIRE)"
_info "Sending: test_login_failed then test_login_success from same IP"
_info "Expected: alert with case_name containing 'TEST_Basic_Sequence'"

# Show exactly what wire message is being sent
TS=$(date "+%b %e %H:%M:%S")
WIRE1="10.99.1.1 $PARSER ${TS} testhost opensiem[1]: test_login_failed event from host"
WIRE2="10.99.1.1 $PARSER ${TS} testhost opensiem[1]: test_login_success event from host"
_info "Wire msg 1: $WIRE1"
_info "Wire msg 2: $WIRE2"

# Verify pattern match before sending
_info "Verifying pattern match in running engine..."
MATCH_CHECK=$(python3 -c "
import sys; sys.path.insert(0, '/opt/opensiem')
import correlation
correlation.load_data()
from modules import parse_syslog
import datetime
ts = datetime.datetime.now().strftime('%b %e %H:%M:%S')
parsed = parse_syslog.parse_log(f'{ts} testhost opensiem[1]: test_login_failed event from host')
matches = correlation.check_message_match(parsed, '10.99.1.1')
if matches:
    print('MATCH:' + ','.join(str(m['message_id']) for m in matches))
else:
    print('NO_MATCH — parsed message field: ' + str(parsed.get('message','')))
" 2>/dev/null | tail -1)
_info "Pattern check result: $MATCH_CHECK"

# Check alerts before sending
BEFORE_COUNT=$(alert_count "TEST_Basic_Sequence")
_info "Alerts matching TEST_Basic_Sequence before sending: $BEFORE_COUNT"

# Send the logs
send_log "10.99.1.1" "$PARSER" "test_login_failed event from host"
sleep 0.5
send_log "10.99.1.1" "$PARSER" "test_login_success event from host"

_info "Logs sent. Waiting up to 15 seconds for alert..."

if wait_for_alert "TEST_Basic_Sequence"; then
    _pass "TEST_Basic_Sequence fired as expected"
else
    # Detailed failure diagnosis
    echo ""
    _info "=== FAILURE DIAGNOSIS ==="

    # Check server logs for our test IP
    _info "Server log entries for 10.99.1.1 (last 30 lines):"
    journalctl -u opensiem.service -n 30 --no-pager 2>/dev/null | \
        grep -i "10.99.1.1\|test_login\|TEST_Basic\|9000\|9001" || \
        echo "    (no matching entries)"

    # Check what's in the correlation engine's in-memory storage
    _info "In-memory correlation state for 10.99.1.1:"
    python3 -c "
import sys; sys.path.insert(0, '/opt/opensiem')
import correlation
correlation.load_data()
bucket = correlation.log_storage.get('10.99.1.1', {})
if bucket:
    for mid, data in bucket.items():
        print(f'  msg_id={mid} occurrences={len(data[\"timestamps\"])} last={data[\"timestamps\"][-1] if data[\"timestamps\"] else None}')
else:
    print('  EMPTY — no steps stored for 10.99.1.1')
print('  All tracked entities:', list(correlation.log_storage.keys()))
" 2>/dev/null

    # Check if alert exists but with different text
    _info "All recent correlation alerts (since test start):"
    $PSQL -c "
        SELECT id, LEFT(admin_note, 80) as note
        FROM alerts
        WHERE alert_type = 'correlation'
          AND id > ${TEST_START_ALERT_ID}
        ORDER BY id DESC LIMIT 5
    " 2>/dev/null || echo "    (query failed)"

    # Check cooldown
    _info "Checking cooldown state for case 900:"
    python3 -c "
import sys; sys.path.insert(0, '/opt/opensiem')
import correlation
key = ('10.99.1.1', 900)
if key in correlation.cooldown_tracker:
    import datetime
    elapsed = (datetime.datetime.now() - correlation.cooldown_tracker[key]).total_seconds()
    print(f'  ON COOLDOWN — last fired {elapsed:.0f}s ago (cooldown=10s)')
else:
    print('  No cooldown active for this entity+case')
" 2>/dev/null

    _fail "TEST_Basic_Sequence did NOT fire"
fi

# =============================================================================
# TEST 2 — Time-window enforcement (should NOT fire — window expires)
# =============================================================================
_head "TEST 2: Time-window enforcement (should NOT fire)"
_info "Window is 5 seconds — sending step 1, waiting 7 seconds, then step 2"

send_log "10.99.2.1" "$PARSER" "test_window_step_one event"
_info "Waiting 7 seconds for window to expire..."
sleep 7
send_log "10.99.2.1" "$PARSER" "test_window_step_two event"
sleep 2

cnt=$(alert_count "TEST_Window_Expired")
if [ "$cnt" -eq 0 ]; then
    _pass "TEST_Window_Expired correctly did NOT fire (window expired)"
else
    _fail "TEST_Window_Expired fired when it should not have (count=$cnt)"
fi

# =============================================================================
# TEST 3 — Sequence ordering (should NOT fire — wrong order)
# =============================================================================
_head "TEST 3: Sequence ordering enforcement (should NOT fire)"
_info "Sending step 2 before step 1 — should not fire"

send_log "10.99.3.1" "$PARSER" "test_order_second event"
sleep 0.5
send_log "10.99.3.1" "$PARSER" "test_order_first event"
sleep 2

cnt=$(alert_count "TEST_Order_Enforced")
if [ "$cnt" -eq 0 ]; then
    _pass "TEST_Order_Enforced correctly did NOT fire (wrong sequence order)"
else
    _fail "TEST_Order_Enforced fired when it should not have (count=$cnt)"
fi

# Now send in correct order — should fire
_info "Now sending in correct order — should fire"
send_log "10.99.3.2" "$PARSER" "test_order_first event"
sleep 0.5
send_log "10.99.3.2" "$PARSER" "test_order_second event"

if wait_for_alert "TEST_Order_Enforced"; then
    _pass "TEST_Order_Enforced fired correctly when steps were in order"
else
    _fail "TEST_Order_Enforced did NOT fire even with correct order"
fi

# =============================================================================
# TEST 4 — User-based entity grouping
# =============================================================================
_head "TEST 4: User-based entity grouping (should FIRE across different IPs)"
_info "Sending fail from 10.99.4.1 and success from 10.99.4.2, same user=testuser"

send_log "10.99.4.1" "$PARSER" "test_user_fail user=testuser from 10.99.4.1"
sleep 0.5
send_log "10.99.4.2" "$PARSER" "test_user_success user=testuser from 10.99.4.2"

if wait_for_alert "TEST_User_Grouping"; then
    _pass "TEST_User_Grouping fired correctly across different IPs"
else
    _fail "TEST_User_Grouping did NOT fire — user-based grouping may not be working"
fi

# =============================================================================
# TEST 5 — Cooldown enforcement
# =============================================================================
_head "TEST 5: Cooldown enforcement (rule fires ONCE, second trigger ignored)"

send_log "10.99.5.1" "$PARSER" "test_cooldown_step_a event"
sleep 0.5
send_log "10.99.5.1" "$PARSER" "test_cooldown_step_b event"

if wait_for_alert "TEST_Cooldown"; then
    _pass "TEST_Cooldown fired on first trigger"
else
    _fail "TEST_Cooldown did NOT fire at all"
fi

_info "Triggering again immediately (should be suppressed by 60s cooldown)"
send_log "10.99.5.1" "$PARSER" "test_cooldown_step_a event"
sleep 0.5
send_log "10.99.5.1" "$PARSER" "test_cooldown_step_b event"
sleep 3

cnt=$(alert_count "TEST_Cooldown")
if [ "$cnt" -le 1 ]; then
    _pass "TEST_Cooldown correctly suppressed second trigger (count=$cnt)"
else
    _fail "TEST_Cooldown fired again during cooldown window (count=$cnt)"
fi

# =============================================================================
# TEST 6 — Threshold-based rule
# =============================================================================
_head "TEST 6: Threshold-based rule (fire after 5 events in 30 seconds)"
_info "Sending 5 threshold events from same IP"

for i in 1 2 3 4 5; do
    send_log "10.99.6.1" "$PARSER" "test_threshold_event number $i"
done

if wait_for_alert "TEST_Threshold"; then
    _pass "TEST_Threshold fired after 5 events as expected"
else
    _fail "TEST_Threshold did NOT fire after 5 events"
fi

# =============================================================================
# TEST 7 — Multi-IP distributed detection
# =============================================================================
_head "TEST 7: Multi-IP distributed detection (global entity_field)"
_info "Sending test_distributed_from_bot from 3 different IPs"
_info "Sending test_distributed_target from another IP"

send_log "10.99.7.1" "$PARSER" "test_distributed_from_bot attack"
send_log "10.99.7.2" "$PARSER" "test_distributed_from_bot attack"
send_log "10.99.7.3" "$PARSER" "test_distributed_from_bot attack"
sleep 0.3
send_log "10.99.7.4" "$PARSER" "test_distributed_target hit"

if wait_for_alert "TEST_Distributed"; then
    _pass "TEST_Distributed fired correctly across multiple IPs"
else
    _fail "TEST_Distributed did NOT fire — global grouping may not be working"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${YLW}══════════════════════════════════════════${NC}"
echo -e "${YLW}  Test Results                            ${NC}"
echo -e "${YLW}══════════════════════════════════════════${NC}"
echo -e "  Total : $total"
echo -e "  ${GRN}Passed: $pass${NC}"
if [ $fail -gt 0 ]; then
    echo -e "  ${RED}Failed: $fail${NC}"
else
    echo -e "  Failed: $fail"
fi
echo ""

if [ $fail -eq 0 ]; then
    echo -e "${GRN}All tests passed. Correlation engine v2 is working correctly.${NC}"
else
    echo -e "${YLW}Some tests failed. Check the OpenSIEM server log for details:${NC}"
    echo -e "  journalctl -u opensiem-server -f"
    echo -e "  or: tail -f /var/log/opensiem/server.log"
fi

# =============================================================================
# Cleanup — remove test use-cases
# =============================================================================
echo ""
read -rp "Remove test use-cases from the database? [y/N]: " CLEANUP
if [[ "$CLEANUP" == "y" || "$CLEANUP" == "Y" ]]; then
    psql -U "$DB_USER" -d "$DB_NAME" << 'SQL'
    BEGIN;
    DELETE FROM special_messages WHERE msg_id  BETWEEN 9000 AND 9099;
    DELETE FROM use_cases        WHERE case_id BETWEEN 900  AND 909;
    COMMIT;
SQL
    curl -s -X POST http://127.0.0.1:51808/reload > /dev/null
    echo -e "${GRN}Test data removed. Engine reloaded.${NC}"
fi
