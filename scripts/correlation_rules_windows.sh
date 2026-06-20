#!/usr/bin/env bash
# =============================================================================
# OpenSIEM Atom v1 — Windows Correlation Rules Seed Script
#
# Seeds Windows Event Log-based correlation rules into use_cases and
# special_messages. Requires parse_windows_evtlog.py to be deployed and
# the Windows watcher forwarding events.
#
# Patterns match the formatted message output of parse_windows_evtlog.py:
#   "Windows {ACTION} [{CHANNEL}:{EVENT_ID}] user={USER} {raw_msg}"
#
# Usage:
#   chmod +x correlation_rules_windows.sh
#   ./correlation_rules_windows.sh
#
# After running, reload the correlation engine without restarting:
#   curl -s -X POST http://127.0.0.1:51808/reload
#
# Windows rules use case_ids 30–49 and msg_ids 300–499
# to avoid colliding with Linux rules (10–22, 100–221).
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
DB_USER="${DB_USER:-$(read_conf user postgres)}"
export PGPASSWORD="${DB_PASSWORD:-$(read_conf password '')}"

PSQL="psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -v ON_ERROR_STOP=1"

echo ""
echo "=================================================="
echo " OpenSIEM — Windows Correlation Rules Installer"
echo " DB: $DB_USER@$DB_HOST:$DB_PORT/$DB_NAME"
echo "=================================================="
echo ""

echo "[*] Checking schema..."
$PSQL -c "SELECT COUNT(*) FROM use_cases;" > /dev/null 2>&1 || {
    echo "[!] ERROR: Cannot connect or 'use_cases' table not found."
    exit 1
}
echo "[✓] Schema OK"
echo ""

$PSQL << 'SQL'

BEGIN;

-- Ensure all Windows patterns are lowercase (engine normalises before matching)
UPDATE special_messages
SET message = lower(message)
WHERE msg_id BETWEEN 300 AND 499;

-- =============================================================================
-- RULE 30 — Windows Brute Force to Successful Login
-- Detects repeated failed logons (4625) from the same IP followed by a
-- successful logon (4624). Classic password spray or brute force success.
-- Severity: high
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity)
VALUES (30, 'Windows Brute Force to Successful Login', 'ip', 'high')
ON CONFLICT (case_id) DO UPDATE SET
    case_name    = EXCLUDED.case_name,
    severity     = EXCLUDED.severity;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(300, 30, 'windows login_failed [security:4625]',  true,  0),
(301, 30, 'windows login_failed [security:4625]',  true,  0),
(302, 30, 'windows login_success [security:4624]', false, 0)
ON CONFLICT (msg_id) DO UPDATE SET message = EXCLUDED.message;


-- =============================================================================
-- RULE 31 — Windows Privileged Logon after Standard Logon
-- Detects a normal logon (4624) immediately followed by a privileged logon
-- (4672 — special privileges assigned). Indicates admin-level access granted.
-- Severity: high
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity)
VALUES (31, 'Windows Privileged Logon After Standard Logon', 'ip', 'high')
ON CONFLICT (case_id) DO UPDATE SET
    case_name = EXCLUDED.case_name,
    severity  = EXCLUDED.severity;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(310, 31, 'windows login_success [security:4624]',    false, 0),
(311, 31, 'windows privileged_logon [security:4672]', false, 0)
ON CONFLICT (msg_id) DO UPDATE SET message = EXCLUDED.message;


-- =============================================================================
-- RULE 32 — Windows Lateral Movement via Explicit Credentials (runas)
-- Detects logon using explicit credentials (4648) — a common lateral movement
-- technique where an attacker uses stolen credentials to access another host.
-- Severity: high
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity)
VALUES (32, 'Windows Lateral Movement via Explicit Credentials', 'ip', 'high')
ON CONFLICT (case_id) DO UPDATE SET
    case_name = EXCLUDED.case_name,
    severity  = EXCLUDED.severity;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(320, 32, 'windows login_failed [security:4625]',  true,  0),
(321, 32, 'windows runas_logon [security:4648]',   false, 0)
ON CONFLICT (msg_id) DO UPDATE SET message = EXCLUDED.message;


-- =============================================================================
-- RULE 33 — Windows New Service Installed after Failed Logons
-- Detects brute force (4625) followed by service installation (7045).
-- Malware and ransomware routinely install a Windows service for persistence.
-- Severity: critical
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity)
VALUES (33, 'Windows Malicious Service Installed after Brute Force', 'ip', 'critical')
ON CONFLICT (case_id) DO UPDATE SET
    case_name = EXCLUDED.case_name,
    severity  = EXCLUDED.severity;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(330, 33, 'windows login_failed [security:4625]',        true,  0),
(331, 33, 'windows service_installed [system:7045]',     false, 0)
ON CONFLICT (msg_id) DO UPDATE SET message = EXCLUDED.message;


-- =============================================================================
-- RULE 34 — Windows Account Created then Immediately Logged In
-- Detects a new user account creation (4720) followed by a logon from the
-- same source. Attackers create backdoor accounts for persistent access.
-- Severity: critical
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity)
VALUES (34, 'Windows Backdoor Account Created and Used', 'ip', 'critical')
ON CONFLICT (case_id) DO UPDATE SET
    case_name = EXCLUDED.case_name,
    severity  = EXCLUDED.severity;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(340, 34, 'windows account_created [security:4720]',  false, 0),
(341, 34, 'windows login_success [security:4624]',    false, 0)
ON CONFLICT (msg_id) DO UPDATE SET message = EXCLUDED.message;


-- =============================================================================
-- RULE 35 — Windows Account Locked Out after Failed Logons
-- Detects a burst of failed logons (4625) resulting in an account lockout
-- (4740). Clear indicator of a brute force or credential stuffing attack.
-- Severity: high
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity)
VALUES (35, 'Windows Account Lockout after Brute Force', 'ip', 'high')
ON CONFLICT (case_id) DO UPDATE SET
    case_name = EXCLUDED.case_name,
    severity  = EXCLUDED.severity;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(350, 35, 'windows login_failed [security:4625]', true,  0),
(351, 35, 'windows login_failed [security:4625]', true,  0),
(352, 35, 'windows account_locked [security:4740]', false, 0)
ON CONFLICT (msg_id) DO UPDATE SET message = EXCLUDED.message;


-- =============================================================================
-- RULE 36 — Windows Scheduled Task Created after Logon
-- Detects logon (4624) followed by scheduled task creation (4698).
-- Attackers use scheduled tasks for persistence and delayed payload execution.
-- Severity: high
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity)
VALUES (36, 'Windows Persistence via Scheduled Task', 'ip', 'high')
ON CONFLICT (case_id) DO UPDATE SET
    case_name = EXCLUDED.case_name,
    severity  = EXCLUDED.severity;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(360, 36, 'windows login_success [security:4624]',  false, 0),
(361, 36, 'windows task_created [security:4698]',   false, 0)
ON CONFLICT (msg_id) DO UPDATE SET message = EXCLUDED.message;


-- =============================================================================
-- RULE 37 — Windows Process Created after Privileged Logon
-- Detects privileged logon (4672) followed by process creation (4688).
-- Admin logon immediately spawning a process is a common post-exploitation
-- indicator. Requires process tracking audit policy to be enabled.
-- Severity: high
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity)
VALUES (37, 'Windows Process Execution after Privileged Logon', 'ip', 'high')
ON CONFLICT (case_id) DO UPDATE SET
    case_name = EXCLUDED.case_name,
    severity  = EXCLUDED.severity;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(370, 37, 'windows privileged_logon [security:4672]', false, 0),
(371, 37, 'windows process_create [security:4688]',   true,  0)
ON CONFLICT (msg_id) DO UPDATE SET message = EXCLUDED.message;


-- =============================================================================
-- RULE 38 — Windows User Added to Privileged Group
-- Detects a logon (4624) followed by a user being added to a security group
-- (4728/4732/4756). Privilege escalation via group membership manipulation.
-- Severity: critical
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity)
VALUES (38, 'Windows Privilege Escalation via Group Membership', 'ip', 'critical')
ON CONFLICT (case_id) DO UPDATE SET
    case_name = EXCLUDED.case_name,
    severity  = EXCLUDED.severity;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(380, 38, 'windows login_success [security:4624]',      false, 0),
(381, 38, 'windows group_member_added [security:4732]', false, 0)
ON CONFLICT (msg_id) DO UPDATE SET message = EXCLUDED.message;


-- =============================================================================
-- RULE 39 — Windows Service Crash followed by New Service Install
-- Detects a service crash (7034) followed by a new service installation
-- (7045). Can indicate a crashed malware service being reinstalled.
-- Severity: high
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity)
VALUES (39, 'Windows Service Crash and Reinstall', 'ip', 'high')
ON CONFLICT (case_id) DO UPDATE SET
    case_name = EXCLUDED.case_name,
    severity  = EXCLUDED.severity;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(390, 39, 'windows service_crashed [system:7034]',   false, 0),
(391, 39, 'windows service_installed [system:7045]', false, 0)
ON CONFLICT (msg_id) DO UPDATE SET message = EXCLUDED.message;


-- =============================================================================
-- RULE 40 — Windows Unexpected Shutdown followed by Service Install
-- Detects an unexpected shutdown (6008 — dirty shutdown, power loss or crash)
-- followed by a new service installation. May indicate malware surviving a
-- crash and re-establishing persistence on reboot.
-- Severity: mid
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity)
VALUES (40, 'Windows Post-Crash Service Installation', 'ip', 'mid')
ON CONFLICT (case_id) DO UPDATE SET
    case_name = EXCLUDED.case_name,
    severity  = EXCLUDED.severity;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(400, 40, 'windows unexpected_shutdown [system:6008]', false, 0),
(401, 40, 'windows service_installed [system:7045]',   false, 0)
ON CONFLICT (msg_id) DO UPDATE SET message = EXCLUDED.message;


-- =============================================================================
-- RULE 41 — Windows Kerberos Pre-Auth Failure followed by NTLM Auth
-- Detects Kerberos pre-authentication failure (4771) followed by an NTLM
-- authentication attempt (4776). Attacker may be downgrading from Kerberos
-- to NTLM to exploit weaker authentication or pass-the-hash.
-- Severity: high
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity)
VALUES (41, 'Windows Kerberos Downgrade to NTLM', 'ip', 'high')
ON CONFLICT (case_id) DO UPDATE SET
    case_name = EXCLUDED.case_name,
    severity  = EXCLUDED.severity;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(410, 41, 'windows kerberos_pre_auth_failed [security:4771]', true,  0),
(411, 41, 'windows ntlm_auth_attempt [security:4776]',        true,  0)
ON CONFLICT (msg_id) DO UPDATE SET message = EXCLUDED.message;


-- =============================================================================
-- Re-normalise all Windows patterns to lowercase
-- =============================================================================
UPDATE special_messages
SET message = lower(message)
WHERE msg_id BETWEEN 300 AND 499;

COMMIT;

-- Summary
SELECT
    uc.case_id,
    uc.case_name,
    uc.severity,
    COUNT(sm.msg_id) AS patterns
FROM use_cases uc
JOIN special_messages sm ON sm.case_id_fk = uc.case_id
WHERE uc.case_id BETWEEN 30 AND 49
GROUP BY uc.case_id, uc.case_name, uc.severity
ORDER BY uc.case_id;

SQL

echo ""
echo "[✓] Windows correlation rules installed."
echo ""
echo "Reload the engine now:"
echo "  curl -s -X POST http://127.0.0.1:51808/reload"
echo ""
