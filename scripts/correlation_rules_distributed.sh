#!/usr/bin/env bash
# =============================================================================
# OpenSIEM Atom v2 — Global / Distributed Attack Detection Rules
#
# Seeds rules that detect coordinated attacks from MULTIPLE source IPs.
# These rules use entity_field='global' — all IPs share one bucket.
# A botnet using 500 different IPs each sending one event will collectively
# trigger these rules. This was impossible in v1.
#
# Rules seeded: 90–96
# Usage:
#   chmod +x correlation_rules_distributed.sh
#   ./correlation_rules_distributed.sh
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
echo " OpenSIEM v2 — Distributed Attack Rules Installer"
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
-- RULE 90 — Distributed Credential Stuffing to Successful Login
-- Many different IPs each attempt a login failure, then ANY IP achieves
-- a successful login. Classic credential stuffing attack using a botnet.
-- entity_field='global' means all IPs share one bucket.
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity,
                       time_window_seconds, cooldown_seconds,
                       threshold_count, threshold_window_seconds)
VALUES (90, 'Distributed Credential Stuffing — Login Success Detected',
        'global', 'critical', 600, 3600, NULL, NULL)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, entity_field=EXCLUDED.entity_field,
    severity=EXCLUDED.severity, time_window_seconds=EXCLUDED.time_window_seconds,
    cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order")
VALUES
    (900, 90, 'authentication failure', true,  0),
    (901, 90, 'authentication failure', true,  0),
    (902, 90, 'authentication failure', true,  0),
    (903, 90, 'accepted password',      false, 0)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


-- =============================================================================
-- RULE 91 — Distributed Web Application Attack
-- Multiple IPs sending SQL injection probes — automated scanner or botnet
-- running a coordinated web attack campaign.
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity,
                       time_window_seconds, cooldown_seconds,
                       threshold_count, threshold_window_seconds)
VALUES (91, 'Distributed Web Application Attack', 'global', 'high', 300, 1800, 10, 120)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, entity_field=EXCLUDED.entity_field,
    severity=EXCLUDED.severity, threshold_count=EXCLUDED.threshold_count,
    threshold_window_seconds=EXCLUDED.threshold_window_seconds,
    cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order")
VALUES
    (910, 91, 'select.*from',       true, 0),
    (911, 91, 'union.*select',      true, 0),
    (912, 91, '../../../etc/passwd',true, 0)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


-- =============================================================================
-- RULE 92 — Coordinated Port Scan from Multiple Sources
-- When 5+ different IPs each contribute connection refused events within 2
-- minutes, it suggests a coordinated reconnaissance campaign — multiple
-- threat actors or a distributed scanner.
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity,
                       time_window_seconds, cooldown_seconds,
                       threshold_count, threshold_window_seconds)
VALUES (92, 'Coordinated Port Scan — Multiple Source IPs', 'global', 'high', 300, 1800, 20, 120)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, entity_field=EXCLUDED.entity_field,
    severity=EXCLUDED.severity, threshold_count=EXCLUDED.threshold_count,
    threshold_window_seconds=EXCLUDED.threshold_window_seconds,
    cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order")
VALUES (920, 92, 'connection refused', true, 0)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


-- =============================================================================
-- RULE 93 — Distributed Windows Brute Force (Spray Attack)
-- Password spray: many IPs each attempt ONE login per account.
-- Individual IP brute force rules miss this — each IP only sends 1 attempt.
-- The global bucket accumulates all failed Windows logons across IPs.
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity,
                       time_window_seconds, cooldown_seconds,
                       threshold_count, threshold_window_seconds)
VALUES (93, 'Distributed Windows Password Spray Attack', 'global', 'critical', 300, 3600, 25, 120)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, entity_field=EXCLUDED.entity_field,
    severity=EXCLUDED.severity, threshold_count=EXCLUDED.threshold_count,
    threshold_window_seconds=EXCLUDED.threshold_window_seconds,
    cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order")
VALUES (930, 93, 'windows login_failed [security:4625]', true, 0)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


-- =============================================================================
-- RULE 94 — Multi-Host Log Tampering (Covering Tracks)
-- Attacker compromises multiple systems and clears logs on each.
-- Isolated log clears look like maintenance — coordinated clears across
-- multiple hosts in a short window indicate active incident response evasion.
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity,
                       time_window_seconds, cooldown_seconds)
VALUES (94, 'Coordinated Log Tampering Across Multiple Hosts',
        'global', 'critical', 300, 3600)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, entity_field=EXCLUDED.entity_field,
    severity=EXCLUDED.severity, time_window_seconds=EXCLUDED.time_window_seconds,
    cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order")
VALUES
    (940, 94, 'wevtutil cl',       true, 0),
    (941, 94, 'clear-eventlog',    true, 0),
    (942, 94, 'wevtutil cl',       true, 0)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


-- =============================================================================
-- RULE 95 — Distributed Ransomware Propagation
-- Multiple hosts within a short window each show service installation and
-- shadow copy deletion — hallmarks of ransomware spreading laterally.
-- =============================================================================
INSERT INTO use_cases (case_id, case_name, entity_field, severity,
                       time_window_seconds, cooldown_seconds)
VALUES (95, 'Distributed Ransomware Propagation Detected',
        'global', 'critical', 900, 7200)
ON CONFLICT (case_id) DO UPDATE SET
    case_name=EXCLUDED.case_name, entity_field=EXCLUDED.entity_field,
    severity=EXCLUDED.severity, time_window_seconds=EXCLUDED.time_window_seconds,
    cooldown_seconds=EXCLUDED.cooldown_seconds;

INSERT INTO special_messages (msg_id, case_id_fk, message, can_repeat, "order")
VALUES
    (950, 95, 'windows service_installed [system:7045]', true,  0),
    (951, 95, 'vssadmin delete shadows',                 true,  0)
ON CONFLICT (msg_id) DO UPDATE SET message=EXCLUDED.message;


UPDATE special_messages
SET message = lower(message)
WHERE msg_id BETWEEN 900 AND 999;

COMMIT;

SELECT
    uc.case_id,
    uc.case_name,
    uc.entity_field,
    uc.severity,
    uc.threshold_count,
    COUNT(sm.msg_id) AS patterns
FROM use_cases uc
JOIN special_messages sm ON sm.case_id_fk = uc.case_id
WHERE uc.case_id BETWEEN 90 AND 99
GROUP BY uc.case_id, uc.case_name, uc.entity_field,
         uc.severity, uc.threshold_count
ORDER BY uc.case_id;

SQL

echo ""
echo "[✓] Distributed attack rules installed (case_ids 90–95)"
echo ""
echo "These rules use entity_field='global' — events from ALL source IPs"
echo "accumulate into one shared bucket. Botnet attacks where each IP"
echo "contributes only one event are now detectable."
echo ""
echo "Reload the engine:"
echo "  curl -s -X POST http://127.0.0.1:51808/reload"
echo ""
