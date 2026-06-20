#!/bin/bash
# =============================================================================
# OpenSIEM Atom v1 — Windows Malicious Artifacts Seed Script
#
# Seeds Windows-specific IOC strings into malicious_artifacts.
# These match against the formatted log lines produced by
# parse_windows_evtlog.py, which outputs lines in the format:
#   "Windows {ACTION} [{CHANNEL}:{EVENT_ID}] user={USER} {raw_message}"
#
# Matching is substring-based — if the artifact string appears anywhere
# in the log line, an alarm is raised.
#
# Usage:
#   chmod +x seed_artifacts_windows.sh
#   ./seed_artifacts_windows.sh
# =============================================================================

set -e

CONF="/etc/opensiem/opensiem.conf"

DB_HOST=$(awk -F'=' '/^\[database\]/,/^\[/ { if($1~/^host/)     print $2 }' "$CONF" | tr -d ' ' | head -1)
DB_PORT=$(awk -F'=' '/^\[database\]/,/^\[/ { if($1~/^port/)     print $2 }' "$CONF" | tr -d ' ' | head -1)
DB_NAME=$(awk -F'=' '/^\[database\]/,/^\[/ { if($1~/^database/) print $2 }' "$CONF" | tr -d ' ' | head -1)
DB_USER=$(awk -F'=' '/^\[database\]/,/^\[/ { if($1~/^user/)     print $2 }' "$CONF" | tr -d ' ' | head -1)
DB_PASS=$(awk -F'=' '/^\[database\]/,/^\[/ { if($1~/^password/) print $2 }' "$CONF" | tr -d ' ' | head -1)

export PGPASSWORD="${DB_PASS}"
PSQL="psql -h $DB_HOST -p ${DB_PORT:-5432} -U $DB_USER -d $DB_NAME -v ON_ERROR_STOP=1"

GRN='\033[0;32m'; YLW='\033[1;33m'; NC='\033[0m'

echo -e "${YLW}══════════════════════════════════════════${NC}"
echo -e "${YLW}  OpenSIEM — Windows Artifact Seeder      ${NC}"
echo -e "${YLW}══════════════════════════════════════════${NC}"
echo ""

$PSQL << 'SQL'

-- =============================================================================
-- CRITICAL — Confirmed high-value attack tools and techniques seen in Windows
-- logs. Immediate investigation required.
-- =============================================================================
INSERT INTO malicious_artifacts (artifacts, severity, source_url) VALUES

-- Known offensive security tools that appear in process creation logs (4688)
-- and Sysmon logs when running on Windows endpoints
('mimikatz',                            'critical', 'opensiem-windows'),
('meterpreter',                         'critical', 'opensiem-windows'),
('cobalt strike',                       'critical', 'opensiem-windows'),
('cobaltstrike',                        'critical', 'opensiem-windows'),
('empire',                              'critical', 'opensiem-windows'),
('metasploit',                          'critical', 'opensiem-windows'),
('bloodhound',                          'critical', 'opensiem-windows'),
('sharphound',                          'critical', 'opensiem-windows'),

-- Process injection and credential dumping techniques visible in 4688/Sysmon
('lsass.exe',                           'critical', 'opensiem-windows'),
('procdump',                            'critical', 'opensiem-windows'),
('sekurlsa',                            'critical', 'opensiem-windows'),
('wce.exe',                             'critical', 'opensiem-windows'),
('fgdump',                              'critical', 'opensiem-windows'),

-- Suspicious PowerShell patterns (visible in 4688 command line logging)
('-encodedcommand',                     'critical', 'opensiem-windows'),
('-enc ',                               'critical', 'opensiem-windows'),
('iex(',                                'critical', 'opensiem-windows'),
('invoke-expression',                   'critical', 'opensiem-windows'),
('downloadstring',                      'critical', 'opensiem-windows'),
('invoke-mimikatz',                     'critical', 'opensiem-windows'),
('invoke-shellcode',                    'critical', 'opensiem-windows'),
('bypass -noprofile',                   'critical', 'opensiem-windows'),

-- Ransomware and destructive tool indicators
('vssadmin delete shadows',             'critical', 'opensiem-windows'),
('wbadmin delete catalog',              'critical', 'opensiem-windows'),
('bcdedit /set recoveryenabled no',     'critical', 'opensiem-windows'),
('cipher /w:',                          'critical', 'opensiem-windows'),

-- Remote code execution via built-in Windows tools (LOLBins)
('wmic process call create',            'critical', 'opensiem-windows'),
('wscript.shell',                       'critical', 'opensiem-windows'),
('certutil -decode',                    'critical', 'opensiem-windows'),
('certutil -urlcache',                  'critical', 'opensiem-windows'),
('regsvr32 /s /u /i:http',             'critical', 'opensiem-windows'),
('rundll32.exe javascript',             'critical', 'opensiem-windows'),
('mshta http',                          'critical', 'opensiem-windows'),

-- Lateral movement tools
('psexec',                              'critical', 'opensiem-windows'),
('wmiexec',                             'critical', 'opensiem-windows'),
('smbexec',                             'critical', 'opensiem-windows'),
('impacket',                            'critical', 'opensiem-windows')

ON CONFLICT (artifacts) DO NOTHING;


-- =============================================================================
-- HIGH — Suspicious but requires context. Known bad patterns that could
-- indicate compromise or active attack preparation.
-- =============================================================================
INSERT INTO malicious_artifacts (artifacts, severity, source_url) VALUES

-- Suspicious service names commonly used by malware (visible in 7045)
('windows defender update service',     'high', 'opensiem-windows'),
('svchost32',                           'high', 'opensiem-windows'),
('windowsupdate',                       'high', 'opensiem-windows'),
('svhost',                              'high', 'opensiem-windows'),

-- Scheduled task patterns (visible in 4698)
('at 00:',                              'high', 'opensiem-windows'),
('schtasks /create',                    'high', 'opensiem-windows'),
('\appdata\roaming\',                   'high', 'opensiem-windows'),
('\appdata\local\temp\',               'high', 'opensiem-windows'),

-- Suspicious registry paths in process command lines
('currentversion\run',                  'high', 'opensiem-windows'),
('currentversion\runonce',              'high', 'opensiem-windows'),
('winlogon\shell',                      'high', 'opensiem-windows'),
('image file execution options',        'high', 'opensiem-windows'),

-- Suspicious process parents (e.g. Word spawning cmd.exe — common macro attack)
('winword.exe cmd',                     'high', 'opensiem-windows'),
('excel.exe cmd',                       'high', 'opensiem-windows'),
('powerpnt.exe cmd',                    'high', 'opensiem-windows'),
('outlook.exe powershell',              'high', 'opensiem-windows'),
('winword.exe powershell',              'high', 'opensiem-windows'),

-- Net commands used for reconnaissance and lateral movement
('net user /add',                       'high', 'opensiem-windows'),
('net localgroup administrators /add',  'high', 'opensiem-windows'),
('net share',                           'high', 'opensiem-windows'),
('net use \\',                          'high', 'opensiem-windows'),

-- Windows Defender disabled via command (visible in 4688)
('set-mppreference -disablerealtimemonitoring', 'high', 'opensiem-windows'),
('sc stop windefend',                   'high', 'opensiem-windows'),
('netsh firewall set opmode disable',   'high', 'opensiem-windows'),
('netsh advfirewall set allprofiles state off', 'high', 'opensiem-windows'),

-- Suspicious Windows Event Log manipulation
('wevtutil cl security',                'high', 'opensiem-windows'),
('wevtutil cl system',                  'high', 'opensiem-windows'),
('wevtutil cl application',             'high', 'opensiem-windows'),
('clear-eventlog',                      'high', 'opensiem-windows'),

-- Pass-the-hash indicators (NTLM auth from unusual sources)
('windows ntlm_auth_attempt [security:4776]', 'high', 'opensiem-windows'),

-- Kerberoasting indicator
('windows kerberos_service_ticket [security:4769]', 'high', 'opensiem-windows')

ON CONFLICT (artifacts) DO NOTHING;


-- =============================================================================
-- MID — Informational / suspicious context needed. Not definitively malicious
-- but warrants attention in combination with other events.
-- =============================================================================
INSERT INTO malicious_artifacts (artifacts, severity, source_url) VALUES

-- Reconnaissance commands in process logs
('ipconfig /all',                       'mid', 'opensiem-windows'),
('whoami /all',                         'mid', 'opensiem-windows'),
('netstat -ano',                        'mid', 'opensiem-windows'),
('tasklist /v',                         'mid', 'opensiem-windows'),
('systeminfo',                          'mid', 'opensiem-windows'),
('nltest /domain_trusts',               'mid', 'opensiem-windows'),
('net group "domain admins"',           'mid', 'opensiem-windows'),

-- RDP-related indicators
('windows share_accessed [security:5140]', 'mid', 'opensiem-windows'),
('rdp-tcp#',                            'mid', 'opensiem-windows'),
('qwinsta',                             'mid', 'opensiem-windows'),
('rwinsta',                             'mid', 'opensiem-windows'),

-- Remote management tools (legitimate but worth tracking)
('psremoting',                          'mid', 'opensiem-windows'),
('enter-pssession',                     'mid', 'opensiem-windows'),
('invoke-command -computername',        'mid', 'opensiem-windows'),

-- Account manipulation indicators
('windows account_created [security:4720]',  'mid', 'opensiem-windows'),
('windows account_deleted [security:4726]',  'mid', 'opensiem-windows'),
('windows group_member_added [security:4732]', 'mid', 'opensiem-windows'),

-- Service configuration changes
('windows service_config_changed [system:7040]', 'mid', 'opensiem-windows'),

-- Application crashes (could indicate exploit attempts)
('windows application_crash [application:1000]', 'mid', 'opensiem-windows')

ON CONFLICT (artifacts) DO NOTHING;


-- Summary
SELECT severity, COUNT(*) AS count
FROM malicious_artifacts
WHERE source_url = 'opensiem-windows'
GROUP BY severity
ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high'     THEN 2
        WHEN 'mid'      THEN 3
        ELSE 4
    END;

SQL

echo ""
echo -e "${GRN}✓ Windows artifacts seeded successfully.${NC}"
echo -e "${GRN}  Check the Artifacts page in Chronicler to confirm.${NC}"
echo ""
