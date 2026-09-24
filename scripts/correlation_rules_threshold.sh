#!/usr/bin/env bash
# =============================================================================
# OpenSIEM Atom v2 — Threshold-Based Correlation Rules
#
# Seeds count-based rules that fire when N events accumulate within M seconds.
# These rules require no specific sequence — pure volume detection.
# Exploits the threshold_count / threshold_window_seconds columns added in v2.
#
# Rules seeded: 50–60
# Usage:
#   chmod +x correlation_rules_threshold.sh
#   ./correlation_rules_threshold.sh
#   curl -s -X POST http://127.0.0.1:51808/reload
# =============================================================================

set -euo pipefail

CONF="/etc/opensiem/opensiem.conf"

read_conf() {
    local key="$1" default="$2"
    if [[ -f "$CONF" ]]; then
        val=$(awk -F'=' "/^\s*${key}\s*=/{gsub(/\s/,\"\",$2); print $2; exit}" "$CONF")
        echo "${val:-$default}"
    else
        echo "$default"
    fi
}

DB_HOST="${DB_HOST:-$(read_conf host 127.0.0.1)}"
DB_PORT="${DB_PORT:-$(read_conf port 5432)}"
DB_NAME="${DB_NAME:-$(read_conf database museum)}"
DB_USER="${DB_USER:-$(read_conf user opensiem)}"
export PGPASSWORD="${DB_PASSWORD:-$(read_conf password '')}"

PSQL="psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -v ON_ERROR_STOP=1"

echo ""
echo "=================================================="
echo " OpenSIEM v2 — Threshold Rules Installer"
echo " DB: $DB_USER@$DB_HOST:$DB_PORT/$DB_NAME"
echo "=================================================="
echo ""

$PSQL -c "SELECT COUNT(*) FROM use_cases;" > /dev/null 2>&1 || {
    echo "[!] ERROR: Cannot connect to database"
    exit 1
}
echo "[✓] Database connection OK"
echo ""

$PSQL << 'SQL'

BEGIN;

-- =============================================================================
-- RULE 50 — Port Scan (Fast)
-- Detects rapid connection refusals from a single IP — classic port scan.
-- 30 refused connections within 60 seconds.
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity,
                       time_window_seconds, cooldown_seconds,
                       threshold_count, threshold_window_seconds)
VALUES (50, 'Port Scan Detected (Fast)', 'ip', 'high', 300, 600, 30, 60)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, severity=EXCLUDED.severity,
    threshold_count=EXCLUDED.threshold_count,
    threshold_window_seconds=EXCLUDED.threshold_window_seconds,
    cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order")
VALUES (500, 50, 'connection refused', true, 0)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


-- =============================================================================
-- RULE 51 — Port Scan (Slow — evasion)
-- Attackers slow-scan to evade fast-scan detection.
-- 50 refused connections within 600 seconds.
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity,
                       time_window_seconds, cooldown_seconds,
                       threshold_count, threshold_window_seconds)
VALUES (51, 'Port Scan Detected (Slow — Evasion)', 'ip', 'mid', 900, 1800, 50, 600)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, severity=EXCLUDED.severity,
    threshold_count=EXCLUDED.threshold_count,
    threshold_window_seconds=EXCLUDED.threshold_window_seconds,
    cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order")
VALUES (510, 51, 'connection refused', true, 0)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


-- =============================================================================
-- RULE 52 — HTTP Brute Force on Login Endpoint
-- Detects repeated 401/403 responses from a single IP against web login pages.
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity,
                       time_window_seconds, cooldown_seconds,
                       threshold_count, threshold_window_seconds)
VALUES (52, 'HTTP Brute Force on Login Endpoint', 'ip', 'high', 300, 600, 20, 60)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, severity=EXCLUDED.severity,
    threshold_count=EXCLUDED.threshold_count,
    threshold_window_seconds=EXCLUDED.threshold_window_seconds,
    cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order")
VALUES
    (520, 52, 'post /login', true, 0),
    (521, 52, 'post /wp-login', true, 0)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


-- =============================================================================
-- RULE 55 — SSH Brute Force — High Rate (Threshold)
-- Complements the existing sequence rule (10) with a pure-volume detector.
-- Fires faster on automated tools that don't care about success/failure mix.
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity,
                       time_window_seconds, cooldown_seconds,
                       threshold_count, threshold_window_seconds)
VALUES (55, 'SSH Brute Force — High Rate', 'ip', 'high', 300, 600, 20, 30)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, severity=EXCLUDED.severity,
    threshold_count=EXCLUDED.threshold_count,
    threshold_window_seconds=EXCLUDED.threshold_window_seconds,
    cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order")
VALUES (550, 55, 'failed password', true, 0)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


-- =============================================================================
-- RULE 56 — Web Scanner / Directory Enumeration
-- Detects 404 floods from a single IP — common in web application scanners
-- like Nikto, DirBuster, gobuster.
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity,
                       time_window_seconds, cooldown_seconds,
                       threshold_count, threshold_window_seconds)
VALUES (56, 'Web Scanner / Directory Enumeration', 'ip', 'mid', 300, 600, 50, 60)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, severity=EXCLUDED.severity,
    threshold_count=EXCLUDED.threshold_count,
    threshold_window_seconds=EXCLUDED.threshold_window_seconds,
    cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order")
VALUES (560, 56, '"get / http', true, 0)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


-- =============================================================================
-- RULE 57 — Windows Failed Logon Storm (Event ID 4625)
-- Threshold variant of the Windows brute force rule.
-- 15 failed Windows logons from the same IP within 60 seconds.
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity,
                       time_window_seconds, cooldown_seconds,
                       threshold_count, threshold_window_seconds)
VALUES (57, 'Windows Failed Logon Storm', 'ip', 'high', 300, 600, 15, 60)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, severity=EXCLUDED.severity,
    threshold_count=EXCLUDED.threshold_count,
    threshold_window_seconds=EXCLUDED.threshold_window_seconds,
    cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order")
VALUES (570, 57, 'windows login_failed [security:4625]', true, 0)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


-- =============================================================================
-- RULE 58 — Repeated Sudo Failures
-- 5 incorrect sudo password attempts within 2 minutes — privilege escalation
-- probe or insider threat testing access boundaries.
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity,
                       time_window_seconds, cooldown_seconds,
                       threshold_count, threshold_window_seconds)
VALUES (58, 'Repeated Sudo Authentication Failures', 'ip', 'high', 300, 600, 5, 120)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, severity=EXCLUDED.severity,
    threshold_count=EXCLUDED.threshold_count,
    threshold_window_seconds=EXCLUDED.threshold_window_seconds,
    cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order")
VALUES (580, 58, 'incorrect password attempts', true, 0)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


UPDATE special_messages
SET message = lower(message)
WHERE msg_id BETWEEN 500 AND 599;

COMMIT;

SELECT
    uc.case_id,
    uc.case_name,
    uc.severity,
    uc.threshold_count,
    uc.threshold_window_seconds,
    COUNT(sm.msg_id) AS patterns
FROM use_cases uc
JOIN special_messages sm ON sm.case_id_fk = uc.case_id
WHERE uc.case_id BETWEEN 50 AND 59
GROUP BY uc.case_id, uc.case_name, uc.severity,
         uc.threshold_count, uc.threshold_window_seconds
ORDER BY uc.case_id;

SQL

echo ""
echo "[✓] Threshold rules installed (case_ids 50–58)"
echo ""
echo "Reload the engine:"
echo "  curl -s -X POST http://127.0.0.1:51808/reload"
echo ""
