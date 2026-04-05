#!/bin/bash

# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024–present
# See LICENSE for details.
# =============================================================================
# OpenSIEM Atom v1 — Malicious Artifacts Seed Script
#
# Inserts IOC artifacts at three severity levels.
# Each artifact is a substring that will appear in real log lines.
# The engine checks: if artifact_string in log_message → raise alarm.
#
# Usage:
#   chmod +x seed_artifacts.sh
#   ./seed_artifacts.sh
# =============================================================================

set -euo pipefail

CONF="/etc/opensiem/opensiem.conf"

read_conf() {
    local key="$1" default="$2"
    if [[ -f "$CONF" ]]; then
        # Fixed awk command with proper syntax
        val=$(awk -F'=' -v key="$key" '
            {
                # Remove whitespace
                gsub(/^[ \t]+|[ \t]+$/, "", $1)
                if ($1 == key) {
                    # Get the value after =, remove whitespace
                    value = $2
                    gsub(/^[ \t]+|[ \t]+$/, "", value)
                    print value
                    exit
                }
            }' "$CONF")
        echo "${val:-$default}"
    else
        echo "$default"
    fi
}

# Read configuration with proper quoting
DB_HOST="${DB_HOST:-$(read_conf "host" "127.0.0.1")}"
DB_PORT="${DB_PORT:-$(read_conf "port" "5432")}"
DB_NAME="${DB_NAME:-$(read_conf "database" "museum")}"
DB_USER="${DB_USER:-$(read_conf "user" "postgres")}"

echo "DB_HOST=$DB_HOST"
echo "DB_PORT=$DB_PORT"
echo "DB_NAME=$DB_NAME"
echo "DB_USER=$DB_USER"

# Password: use PGPASSWORD env var or let psql use .pgpass / peer auth
DB_PASSWORD_VAL="$(read_conf "password" "")"
export PGPASSWORD="${DB_PASSWORD:-$DB_PASSWORD_VAL}"

echo "DB_PASS=${PGPASSWORD:+*****}"  # Don't echo actual password

PSQL="psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -v ON_ERROR_STOP=1"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; NC='\033[0m'
echo -e "${YLW}══════════════════════════════════════════${NC}"
echo -e "${YLW}  OpenSIEM — Malicious Artifacts Seeder  ${NC}"
echo -e "${YLW}══════════════════════════════════════════${NC}"
echo ""

$PSQL << 'SQL'

-- =============================================================================
-- SOURCE: OpenSIEM internal test artifacts
-- ON CONFLICT DO NOTHING — never overwrites manually added entries
-- =============================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- HIGH SEVERITY
-- Confirmed malicious: known attack tools, C2 indicators, rootkit strings,
-- exploit payloads. Immediate investigation required.
-- ─────────────────────────────────────────────────────────────────────────────
INSERT INTO malicious_artifacts (artifacts, severity, source_url) VALUES

-- Reverse shell / command execution payloads
('/bin/bash -i >& /dev/tcp/',        'high', 'opensiem-internal'),
('bash -i >& /dev/tcp/',             'high', 'opensiem-internal'),
('python3 -c import socket',         'high', 'opensiem-internal'),
('/tmp/exec',                        'high', 'opensiem-internal'),
('chmod +x /tmp/',                   'high', 'opensiem-internal'),
('curl -o /tmp/',                    'high', 'opensiem-internal'),
('wget -O /tmp/',                    'high', 'opensiem-internal'),

-- Known C2 / malware infrastructure
('185.220.101.5',                    'high', 'opensiem-internal'),   -- Known Tor exit / attacker IP
('45.33.32.156',                     'high', 'opensiem-internal'),   -- Known C2 IP
('194.165.16.11',                    'high', 'opensiem-internal'),   -- Known malware C2
('meterpreter',                      'high', 'opensiem-internal'),
('metasploit',                       'high', 'opensiem-internal'),
('mimikatz',                         'high', 'opensiem-internal'),
('cobalt strike',                    'high', 'opensiem-internal'),
('cobaltstrike',                     'high', 'opensiem-internal'),

-- Privilege escalation / persistence
('sudo -l',                          'high', 'opensiem-internal'),
('/etc/cron.d/malware',              'high', 'opensiem-internal'),
('COMMAND=/bin/bash',                'high', 'opensiem-internal'),   -- sudo to full shell
('useradd -o -u 0',                  'high', 'opensiem-internal'),   -- creating root-uid user
('passwd root',                      'high', 'opensiem-internal'),
('echo root:',                       'high', 'opensiem-internal'),   -- chpasswd style

-- Credential dumping
('/etc/shadow',                      'high', 'opensiem-internal'),
('cat /etc/passwd',                  'high', 'opensiem-internal'),
('unshadow',                         'high', 'opensiem-internal'),
('john --wordlist',                  'high', 'opensiem-internal'),
('hashcat',                          'high', 'opensiem-internal'),

-- Ransomware indicators
('.locked',                          'high', 'opensiem-internal'),
('.encrypted',                       'high', 'opensiem-internal'),
('READ_ME_FOR_DECRYPT',              'high', 'opensiem-internal'),
('YOUR_FILES_ARE_ENCRYPTED',         'high', 'opensiem-internal'),

-- Web shell indicators
('cmd.php',                          'high', 'opensiem-internal'),
('shell.php',                        'high', 'opensiem-internal'),
('c99.php',                          'high', 'opensiem-internal'),
('r57.php',                          'high', 'opensiem-internal'),
('eval(base64_decode',               'high', 'opensiem-internal'),
('passthru($_',                      'high', 'opensiem-internal'),
('system($_GET',                     'high', 'opensiem-internal')

ON CONFLICT (artifacts) DO NOTHING;


-- ─────────────────────────────────────────────────────────────────────────────
-- MID SEVERITY
-- Suspicious but not confirmed: scanning tools, recon activity,
-- suspicious commands, grey-listed patterns.
-- ─────────────────────────────────────────────────────────────────────────────
INSERT INTO malicious_artifacts (artifacts, severity, source_url) VALUES

-- Scanning / enumeration tools
('nmap',                             'mid', 'opensiem-internal'),
('masscan',                          'mid', 'opensiem-internal'),
('nikto',                            'mid', 'opensiem-internal'),
('gobuster',                         'mid', 'opensiem-internal'),
('dirsearch',                        'mid', 'opensiem-internal'),
('sqlmap',                           'mid', 'opensiem-internal'),
('hydra',                            'mid', 'opensiem-internal'),
('medusa',                           'mid', 'opensiem-internal'),
('burpsuite',                        'mid', 'opensiem-internal'),

-- Suspicious file access patterns
('/proc/sysrq-trigger',              'mid', 'opensiem-internal'),
('/proc/mem',                        'mid', 'opensiem-internal'),
('/.ssh/authorized_keys',            'mid', 'opensiem-internal'),
('/root/.bash_history',              'mid', 'opensiem-internal'),

-- Common attack paths / URIs
('/../../../etc/passwd',             'mid', 'opensiem-internal'),   -- path traversal
('/etc/passwd HTTP',                 'mid', 'opensiem-internal'),
('UNION SELECT',                     'mid', 'opensiem-internal'),   -- SQLi
(''' OR ''1''=''1',                  'mid', 'opensiem-internal'),   -- SQLi (escaped)
('<script>alert',                    'mid', 'opensiem-internal'),   -- XSS
('../etc/passwd',                    'mid', 'opensiem-internal'),   -- LFI
('/wp-config.php',                   'mid', 'opensiem-internal'),   -- WP config grab
('/xmlrpc.php',                      'mid', 'opensiem-internal'),   -- WP brute force vector
('/phpmyadmin',                      'mid', 'opensiem-internal'),

-- Suspicious user agents / tools
('python-requests',                  'mid', 'opensiem-internal'),
('Go-http-client',                   'mid', 'opensiem-internal'),
('zgrab',                            'mid', 'opensiem-internal'),
('curl/7',                           'mid', 'opensiem-internal'),
('Nuclei',                           'mid', 'opensiem-internal'),

-- Suspicious commands
('nc -e /bin/bash',                  'mid', 'opensiem-internal'),
('nc -lvp',                          'mid', 'opensiem-internal'),   -- netcat listener
('base64 -d',                        'mid', 'opensiem-internal'),   -- decode hidden payload
('history -c',                       'mid', 'opensiem-internal'),   -- clearing history
('unset HISTFILE',                   'mid', 'opensiem-internal')    -- disabling history

ON CONFLICT (artifacts) DO NOTHING;


-- ─────────────────────────────────────────────────────────────────────────────
-- LOW SEVERITY
-- Informational: deprecated software, unusual but not malicious,
-- automated scanners hitting non-sensitive paths.
-- ─────────────────────────────────────────────────────────────────────────────
INSERT INTO malicious_artifacts (artifacts, severity, source_url) VALUES

-- Deprecated / sensitive URIs (often scanned)
('/.env',                            'low', 'opensiem-internal'),
('/.git/config',                     'low', 'opensiem-internal'),
('/.DS_Store',                       'low', 'opensiem-internal'),
('/backup.sql',                      'low', 'opensiem-internal'),
('/backup.zip',                      'low', 'opensiem-internal'),
('/admin.php',                       'low', 'opensiem-internal'),
('/wp-login.php',                    'low', 'opensiem-internal'),
('/administrator',                   'low', 'opensiem-internal'),   -- Joomla admin
('/manager/html',                    'low', 'opensiem-internal'),   -- Tomcat manager

-- Recon indicators (low confidence)
('User-Agent: masscan',              'low', 'opensiem-internal'),
('Shodan',                           'low', 'opensiem-internal'),
('censys',                           'low', 'opensiem-internal'),
('zgrab2',                           'low', 'opensiem-internal'),

-- Auth failures at high volume (single hit = low, pattern = correlation rule)
('authentication failure',           'low', 'opensiem-internal'),
('invalid user',                     'low', 'opensiem-internal'),
('Connection closed by authenticating', 'low', 'opensiem-internal'),

-- Unusual but not necessarily malicious
('DROP TABLE',                       'low', 'opensiem-internal'),
('TRUNCATE TABLE',                   'low', 'opensiem-internal'),
('/dev/null 2>&1',                   'low', 'opensiem-internal'),   -- background process hiding
('nohup',                            'low', 'opensiem-internal')    -- persistent background process

ON CONFLICT (artifacts) DO NOTHING;

-- Summary
SELECT severity, COUNT(*) as count
FROM malicious_artifacts
WHERE source_url = 'opensiem-internal'
GROUP BY severity
ORDER BY
    CASE severity WHEN 'high' THEN 1 WHEN 'mid' THEN 2 ELSE 3 END;

SQL

echo ""
echo -e "${GRN}✓ Artifacts seeded successfully.${NC}"
echo -e "${GRN}  Check the Artifacts page in Chronicler to confirm.${NC}"
echo ""
