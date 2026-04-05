#!/usr/bin/env bash
# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024–present
# See LICENSE for details.
# =============================================================================
# OpenSIEM Atom v1 — Correlation Rules Seed Script
#
# Usage:
#   chmod +x correlation_rules.sh
#   ./correlation_rules.sh
#
# The script reads DB credentials from /etc/opensiem/opensiem.conf
# (same file your server uses). You can override them with env vars:
#   DB_HOST=127.0.0.1 DB_NAME=museum DB_USER=postgres ./correlation_rules.sh
#
# After running, trigger a rule reload without restarting the server:
#   curl -s -X POST http://127.0.0.1:51808/reload
# =============================================================================

set -euo pipefail

# ── Read credentials from opensiem.conf (fallback to env / defaults) ──────────
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
# Password: use PGPASSWORD env var or let psql use .pgpass / peer auth
export PGPASSWORD="${DB_PASSWORD:-$(read_conf password '')}"

PSQL="psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -v ON_ERROR_STOP=1"

echo ""
echo "=================================================="
echo " OpenSIEM — Correlation Rules Installer"
echo " DB: $DB_USER@$DB_HOST:$DB_PORT/$DB_NAME"
echo "=================================================="
echo ""

# ── Helper: run SQL quietly, print result ─────────────────────────────────────
run_sql() {
    $PSQL --tuples-only -c "$1" 2>&1
}

# ── Safety check: confirm tables exist ───────────────────────────────────────
echo "[*] Checking schema..."
$PSQL -c "SELECT COUNT(*) FROM use_cases;" > /dev/null 2>&1 || {
    echo "[!] ERROR: Cannot connect or 'use_cases' table not found."
    echo "    Make sure OpenSIEM DB is initialised before running this script."
    exit 1
}
echo "[✓] Schema OK"
echo ""

# =============================================================================
# The SQL block — all rules in a single transaction so it's all-or-nothing
# =============================================================================
$PSQL << 'SQL'

BEGIN;

-- ============================================================================
-- Ensure msg_id sequence exists (msg_id is NOT SERIAL by default in your
-- schema, so we track IDs manually and use ON CONFLICT to stay idempotent).
-- We start our IDs at 100 to leave room below for the user's own test rules.
--
-- IMPORTANT: The correlation engine normalises all message text to lowercase
-- before matching. Every pattern in special_messages must therefore be
-- lowercase so the substring match works correctly.
-- ============================================================================

-- ─── Fix any previously inserted mixed-case patterns ─────────────────────────
-- Run these UPDATEs so existing installations don't need to drop and re-seed.
UPDATE special_messages SET message = lower(message)
WHERE msg_id BETWEEN 100 AND 221;

-- ────────────────────────────────────────────────────────────────────────────
-- RULE SET 1 — SSH Brute Force → Successful Login
-- Modules: parse_ssh.py or parse_auth.py
-- ────────────────────────────────────────────────────────────────────────────
INSERT INTO use_cases (case_id, case_name, entity_field)
VALUES (10, 'SSH Brute Force to Successful Login', 'ip')
ON CONFLICT (case_id) DO NOTHING;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(100, 10, 'ssh login failed',    true,  0),
(101, 10, 'ssh login accepted',  false, 0)
ON CONFLICT (msg_id) DO UPDATE SET message = EXCLUDED.message;


-- ────────────────────────────────────────────────────────────────────────────
-- RULE SET 2 — SSH Invalid User Scan
-- ────────────────────────────────────────────────────────────────────────────
INSERT INTO use_cases (case_id, case_name, entity_field)
VALUES (11, 'SSH Invalid User Scan', 'ip')
ON CONFLICT (case_id) DO NOTHING;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(110, 11, 'ssh invalid user', true, 0),
(111, 11, 'ssh invalid user', true, 0)
ON CONFLICT (msg_id) DO UPDATE SET message = EXCLUDED.message;


-- ────────────────────────────────────────────────────────────────────────────
-- RULE SET 3 — Firewall Block + SSH Attempt
-- ────────────────────────────────────────────────────────────────────────────
INSERT INTO use_cases (case_id, case_name, entity_field)
VALUES (12, 'Firewall Block with Continued SSH Attempt', 'ip')
ON CONFLICT (case_id) DO NOTHING;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(120, 12, 'ufw block',        true,  0),
(121, 12, 'ssh login failed', true,  0)
ON CONFLICT (msg_id) DO UPDATE SET message = EXCLUDED.message;


-- ────────────────────────────────────────────────────────────────────────────
-- RULE SET 4 — SSH Login → Sudo Escalation
-- ────────────────────────────────────────────────────────────────────────────
INSERT INTO use_cases (case_id, case_name, entity_field)
VALUES (13, 'SSH Login followed by Sudo Escalation', 'ip')
ON CONFLICT (case_id) DO NOTHING;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(130, 13, 'ssh login accepted', false, 1),
(131, 13, 'sudo:',              true,  0)
ON CONFLICT (msg_id) DO UPDATE SET message = EXCLUDED.message;


-- ────────────────────────────────────────────────────────────────────────────
-- RULE SET 5 — Database Auth Failure + Web Probe
-- Note: use 'http/1' not just 'get' to avoid matching every log line
-- ────────────────────────────────────────────────────────────────────────────
INSERT INTO use_cases (case_id, case_name, entity_field)
VALUES (14, 'Database Auth Failure with Web Probe', 'ip')
ON CONFLICT (case_id) DO NOTHING;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(140, 14, 'postgresql auth failure', true,  0),
(141, 14, 'http/1',                  true,  0)
ON CONFLICT (msg_id) DO UPDATE SET message = EXCLUDED.message;


-- ────────────────────────────────────────────────────────────────────────────
-- RULE SET 6 — Web Directory Scanner (404 storm)
-- ────────────────────────────────────────────────────────────────────────────
INSERT INTO use_cases (case_id, case_name, entity_field)
VALUES (15, 'Web Directory Scanner Detected', 'ip')
ON CONFLICT (case_id) DO NOTHING;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(150, 15, '" 404 ', true, 0),
(151, 15, '" 404 ', true, 0)
ON CONFLICT (msg_id) DO UPDATE SET message = EXCLUDED.message;


-- ────────────────────────────────────────────────────────────────────────────
-- RULE SET 7 — AppArmor Denial + OOM Kill
-- ────────────────────────────────────────────────────────────────────────────
INSERT INTO use_cases (case_id, case_name, entity_field)
VALUES (16, 'AppArmor Denial with OOM Kill', 'ip')
ON CONFLICT (case_id) DO NOTHING;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(160, 16, 'apparmor denied',  true, 0),
(161, 16, 'oom killer killed', true, 0)
ON CONFLICT (msg_id) DO UPDATE SET message = EXCLUDED.message;


-- ────────────────────────────────────────────────────────────────────────────
-- RULE SET 8 — MySQL Auth Failure + Web Request
-- Note: use 'http/1' not just 'post' to avoid matching every log line
-- ────────────────────────────────────────────────────────────────────────────
INSERT INTO use_cases (case_id, case_name, entity_field)
VALUES (17, 'MySQL Auth Failure with Web Request', 'ip')
ON CONFLICT (case_id) DO NOTHING;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(170, 17, 'password authentication failed', true, 0),
(171, 17, 'http/1',                         true, 0)
ON CONFLICT (msg_id) DO UPDATE SET message = EXCLUDED.message;


-- ────────────────────────────────────────────────────────────────────────────
-- RULE SET 9 — Cron Job + Outbound Block (Persistence + C2)
-- Note: use 'ufw block' not just 'block' to avoid false positives
-- ────────────────────────────────────────────────────────────────────────────
INSERT INTO use_cases (case_id, case_name, entity_field)
VALUES (18, 'Suspicious Cron Job with Outbound Block', 'ip')
ON CONFLICT (case_id) DO NOTHING;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(180, 18, 'cron job:', true, 1),
(181, 18, 'ufw block', true, 0)
ON CONFLICT (msg_id) DO UPDATE SET message = EXCLUDED.message;


-- ────────────────────────────────────────────────────────────────────────────
-- RULE SET 10 — Multi-Service Credential Stuffing
-- ────────────────────────────────────────────────────────────────────────────
INSERT INTO use_cases (case_id, case_name, entity_field)
VALUES (19, 'Multi-Service Credential Stuffing', 'ip')
ON CONFLICT (case_id) DO NOTHING;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(190, 19, 'ssh login failed', true, 0),
(191, 19, '" 401 ',           true, 0)
ON CONFLICT (msg_id) DO UPDATE SET message = EXCLUDED.message;


-- ────────────────────────────────────────────────────────────────────────────
-- RULE SET 11 — Audit Syscall After SSH Login (Post-Exploitation)
-- ────────────────────────────────────────────────────────────────────────────
INSERT INTO use_cases (case_id, case_name, entity_field)
VALUES (20, 'Audit Syscall After SSH Login (Post-Exploitation)', 'ip')
ON CONFLICT (case_id) DO NOTHING;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(200, 20, 'ssh login accepted', false, 1),
(201, 20, 'audit syscall',      true,  0)
ON CONFLICT (msg_id) DO UPDATE SET message = EXCLUDED.message;


-- ────────────────────────────────────────────────────────────────────────────
-- RULE SET 12 — Web 500 + Database Error
-- Note: use 'postgresql error' not just 'postgresql' to avoid matching
-- every PostgreSQL log line (connections, slow queries etc.)
-- ────────────────────────────────────────────────────────────────────────────
INSERT INTO use_cases (case_id, case_name, entity_field)
VALUES (21, 'Web 500 Errors with Database Error', 'ip')
ON CONFLICT (case_id) DO NOTHING;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(210, 21, '" 500 ',           true, 0),
(211, 21, 'postgresql error', true, 0)
ON CONFLICT (msg_id) DO UPDATE SET message = EXCLUDED.message;


-- ────────────────────────────────────────────────────────────────────────────
-- RULE SET 13 — Repeated SELinux AVC Denial
-- ────────────────────────────────────────────────────────────────────────────
INSERT INTO use_cases (case_id, case_name, entity_field)
VALUES (22, 'Repeated SELinux AVC Denial', 'ip')
ON CONFLICT (case_id) DO NOTHING;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order") VALUES
(220, 22, 'selinux avc denied', true, 0),
(221, 22, 'selinux avc denied', true, 0)
ON CONFLICT (msg_id) DO UPDATE SET message = EXCLUDED.message;


COMMIT;

SQL

echo ""
echo "=================================================="
echo " Rules installed successfully!"
echo ""
echo " Use cases added:"
echo "   10  SSH Brute Force to Successful Login"
echo "   11  SSH Invalid User Scan"
echo "   12  Firewall Block with Continued SSH Attempt"
echo "   13  SSH Login followed by Sudo Escalation"
echo "   14  Database Auth Failure with Web Probe"
echo "   15  Web Directory Scanner Detected"
echo "   16  AppArmor Denial with OOM Kill"
echo "   17  MySQL Auth Failure with Web Request"
echo "   18  Suspicious Cron Job with Outbound Block"
echo "   19  Multi-Service Credential Stuffing"
echo "   20  Audit Syscall After SSH Login"
echo "   21  Web 500 Errors with Database Error"
echo "   22  Repeated SELinux AVC Denial"
echo ""
echo " Reload rules into running engine (no restart needed):"
echo "   curl -s -X POST http://127.0.0.1:51808/reload"
echo "=================================================="
echo ""

# Auto-reload if server is running
if curl -s --connect-timeout 2 -X POST http://127.0.0.1:51808/reload > /dev/null 2>&1; then
    echo "[✓] Correlation engine reloaded automatically."
else
    echo "[i] Engine not running or reload skipped — rules will load on next start."
fi
echo ""
