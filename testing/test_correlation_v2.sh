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
DB_USER="${DB_USER:-waqar}"

PSQL="psql -U $DB_USER -d $DB_NAME -v ON_ERROR_STOP=1 -t -A"

GRN='\033[0;32m'; RED='\033[0;31m'; YLW='\033[1;33m'; BLU='\033[0;34m'; NC='\033[0m'

pass=0; fail=0; total=0

_pass() { echo -e "  ${GRN}✓ PASS${NC}: $1"; ((pass++)); ((total++)); }
_fail() { echo -e "  ${RED}✗ FAIL${NC}: $1"; ((fail++)); ((total++)); }
_info() { echo -e "  ${BLU}ℹ${NC}  $1"; }
_head() { echo -e "\n${YLW}══ $1 ══${NC}"; }

# =============================================================================
# Helpers
# =============================================================================

send_log() {
    local src_ip="$1"
    local parser="$2"
    local message="$3"
    printf '%s %s %s\n' "$src_ip" "$parser" "$message" \
        | nc -q1 "$SERVER_IP" "$SERVER_PORT" 2>/dev/null || true
    sleep 0.2
}

alert_count() {
    local case_name="$1"
    local since="${2:-1 minute}"
    $PSQL -c "
        SELECT COUNT(*) FROM alerts
        WHERE admin_note LIKE '%${case_name}%'
          AND created_at >= now() - interval '${since}'
    " 2>/dev/null || echo 0
}

wait_for_alert() {
    local case_name="$1"
    local max_wait="${2:-8}"
    local elapsed=0
    while [ $elapsed -lt $max_wait ]; do
        cnt=$(alert_count "$case_name" "30 seconds")
        if [ "$cnt" -gt 0 ]; then return 0; fi
        sleep 1; ((elapsed++))
    done
    return 1
}

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
sleep 1

PARSER="modules/parse_syslog.py"

# =============================================================================
# TEST 1 — Basic sequence rule
# =============================================================================
_head "TEST 1: Basic sequence rule (should FIRE)"
_info "Sending: test_login_failed then test_login_success from same IP"

send_log "10.99.1.1" "$PARSER" "test_login_failed event from host"
sleep 0.5
send_log "10.99.1.1" "$PARSER" "test_login_success event from host"

if wait_for_alert "TEST_Basic_Sequence"; then
    _pass "TEST_Basic_Sequence fired as expected"
else
    _fail "TEST_Basic_Sequence did NOT fire — check engine is running"
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

cnt=$(alert_count "TEST_Window_Expired" "30 seconds")
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

cnt=$(alert_count "TEST_Order_Enforced" "30 seconds")
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

cnt=$(alert_count "TEST_Cooldown" "15 seconds")
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
