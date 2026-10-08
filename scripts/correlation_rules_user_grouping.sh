#!/usr/bin/env bash
# =============================================================================
# OpenSIEM Atom v2 — User-Based Grouping Correlation Rules
#
# Seeds rules that track attack sequences by USERNAME across multiple IPs.
# These rules only work with OpenSIEM v2's entity_field='user' feature.
# In v1, all rules grouped by source IP — lateral movement using stolen
# credentials across different machines was completely invisible.
#
# Prerequisites:
#   - Parsers that emit user=<username> in log lines (SSH, auth, Windows)
#   - OpenSIEM correlation.py v2 deployed
#
# Rules seeded: 70–77
# Usage:
#   chmod +x correlation_rules_user_grouping.sh
#   ./correlation_rules_user_grouping.sh
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
echo " OpenSIEM v2 — User-Based Grouping Rules Installer"
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
-- RULE 70 — Credential Reuse Across Servers (Lateral Movement)
-- Detects the same user failing authentication on one system then succeeding
-- on another — a hallmark of stolen credentials used for lateral movement.
-- The two events can come from DIFFERENT source IPs.
-- entity_field='user' groups events by username, not IP.
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity,
                       time_window_seconds, cooldown_seconds)
VALUES (70, 'Credential Reuse — Lateral Movement Detected', 'user', 'critical', 600, 1800)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, entity_field=EXCLUDED.entity_field,
    severity=EXCLUDED.severity, time_window_seconds=EXCLUDED.time_window_seconds,
    cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order")
VALUES
    (700, 70, 'authentication failure', true,  0),
    (701, 70, 'accepted publickey',     false, 0)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


-- =============================================================================
-- RULE 71 — User Enumeration to Valid Account Takeover
-- Detects repeated "invalid user" attempts (probing for valid usernames) from
-- any IP, followed by a successful login for a valid username.
-- Groups by user so cross-IP enumeration is caught.
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity,
                       time_window_seconds, cooldown_seconds)
VALUES (71, 'User Enumeration Followed by Successful Login', 'user', 'high', 300, 1800)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, entity_field=EXCLUDED.entity_field,
    severity=EXCLUDED.severity, time_window_seconds=EXCLUDED.time_window_seconds,
    cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order")
VALUES
    (710, 71, 'invalid user',       true,  0),
    (711, 71, 'accepted password',  false, 0)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


-- =============================================================================
-- RULE 72 — Privilege Escalation after Lateral Movement
-- Detects a user logging in remotely then immediately escalating via sudo.
-- Groups by username so this fires even if the SSH source IP differs from
-- the sudo event's host IP.
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity,
                       time_window_seconds, cooldown_seconds)
VALUES (72, 'Privilege Escalation after Remote Login', 'user', 'critical', 900, 3600)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, entity_field=EXCLUDED.entity_field,
    severity=EXCLUDED.severity, time_window_seconds=EXCLUDED.time_window_seconds,
    cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order")
VALUES
    (720, 72, 'accepted password',    false, 1),
    (721, 72, 'sudo:.*command',       false, 2)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


-- =============================================================================
-- RULE 73 — Windows Credential Reuse Across Domains
-- Same user fails Windows logon (4625) on one machine then succeeds (4624)
-- on another — cross-machine credential stuffing or pass-the-hash.
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity,
                       time_window_seconds, cooldown_seconds)
VALUES (73, 'Windows Credential Reuse Across Machines', 'user', 'critical', 600, 1800)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, entity_field=EXCLUDED.entity_field,
    severity=EXCLUDED.severity, time_window_seconds=EXCLUDED.time_window_seconds,
    cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order")
VALUES
    (730, 73, 'windows login_failed [security:4625]',  true,  0),
    (731, 73, 'windows login_success [security:4624]', false, 0)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


-- =============================================================================
-- RULE 74 — Service Account Used Interactively
-- Service accounts should never have interactive logins. If a service account
-- (common naming: svc_, sa_, _svc) fails then succeeds interactively across
-- any machines, it signals credential theft.
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity,
                       time_window_seconds, cooldown_seconds)
VALUES (74, 'Service Account Interactive Login', 'user', 'critical', 600, 3600)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, entity_field=EXCLUDED.entity_field,
    severity=EXCLUDED.severity, time_window_seconds=EXCLUDED.time_window_seconds,
    cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order")
VALUES
    (740, 74, 'session opened for user svc',     false, 0),
    (741, 74, 'windows privileged_logon [security:4672]', false, 0)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


-- =============================================================================
-- RULE 75 — Database Direct Access After Application Auth Failure
-- Attacker fails web/app authentication then attempts direct database
-- connection with the same credentials — bypassing the application layer.
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity,
                       time_window_seconds, cooldown_seconds)
VALUES (75, 'Database Direct Access After App Auth Failure', 'user', 'critical', 600, 3600)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, entity_field=EXCLUDED.entity_field,
    severity=EXCLUDED.severity, time_window_seconds=EXCLUDED.time_window_seconds,
    cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order")
VALUES
    (750, 75, 'authentication failure',          true,  1),
    (751, 75, 'connection received.*postgres',   false, 2)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


UPDATE special_messages
SET message = lower(message)
WHERE msg_id BETWEEN 700 AND 799;

COMMIT;

SELECT
    uc.case_id,
    uc.case_name,
    uc.entity_field,
    uc.severity,
    uc.time_window_seconds,
    COUNT(sm.msg_id) AS patterns
FROM use_cases uc
JOIN special_messages sm ON sm.case_id_fk = uc.case_id
WHERE uc.case_id BETWEEN 70 AND 79
GROUP BY uc.case_id, uc.case_name, uc.entity_field,
         uc.severity, uc.time_window_seconds
ORDER BY uc.case_id;

SQL

echo ""
echo "[✓] User-grouping rules installed (case_ids 70–75)"
echo ""
echo "These rules group events by USERNAME not IP."
echo "They detect lateral movement and credential reuse across multiple machines."
echo ""
echo "Reload the engine:"
echo "  curl -s -X POST http://127.0.0.1:51808/reload"
echo ""
