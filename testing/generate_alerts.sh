#!/usr/bin/env bash
# =============================================================================
# OpenSIEM — Alert Generation Script
# Sends crafted log lines that trigger existing correlation rules,
# artifact detections, and threshold rules to populate the alerts table.
#
# Usage:
#   chmod +x generate_alerts.sh
#   ./generate_alerts.sh [server_ip] [port]
#
# Defaults: server_ip=127.0.0.1  port=11514
# =============================================================================

SERVER_IP="${1:-127.0.0.1}"
SERVER_PORT="${2:-11514}"
CERT_PATH="${CERT_PATH:-/etc/opensiem/certs/server.crt}"
PARSER_SYSLOG="modules/parse_syslog.py"
PARSER_AUTH="modules/parse_auth.py"
PARSER_SSH="modules/parse_ssh.py"

GRN='\033[0;32m'; YLW='\033[1;33m'; NC='\033[0m'

# Auto-detect TLS
TLS_MODE="false"
if openssl s_client -connect "${SERVER_IP}:${SERVER_PORT}" \
   -CAfile "$CERT_PATH" </dev/null 2>/dev/null | grep -q "Verify return code"; then
    TLS_MODE="true"
fi
echo -e "${YLW}Mode: $([ "$TLS_MODE" = "true" ] && echo TLS || echo Plaintext)${NC}"

send_log() {
    local src_ip="$1"
    local parser="$2"
    local message="$3"
    local ts
    ts=$(LC_ALL=C date "+%b %e %H:%M:%S")
    local wire="${src_ip} ${parser} ${ts} targethost opensiem[1]: ${message}"

    if [[ "$TLS_MODE" == "true" ]]; then
        printf '%s\r\n' "$wire" | \
            timeout 20 openssl s_client \
                -connect "${SERVER_IP}:${SERVER_PORT}" \
                -CAfile "$CERT_PATH" \
                -quiet -ign_eof 2>/dev/null || true
    else
        printf '%s\n' "$wire" | \
            nc -q1 "$SERVER_IP" "$SERVER_PORT" 2>/dev/null || true
    fi
    sleep 0.5
}

count_alerts() {
    psql -U opensiem -d museum -tAc "SELECT COUNT(*) FROM alerts" 2>/dev/null || echo 0
}

BEFORE=$(count_alerts)
echo -e "Alerts before: ${BEFORE}"
echo ""

# =============================================================================
# 1. SSH Brute Force → Success (triggers rule 10)
# =============================================================================
echo -e "${YLW}[1] SSH Brute Force to Successful Login...${NC}"
for i in 1 2 3; do
    send_log "203.0.113.${i}" "$PARSER_AUTH" \
        "Failed password for root from 203.0.113.${i} port 2244${i} ssh2"
done
sleep 1
send_log "203.0.113.1" "$PARSER_AUTH" \
    "Accepted password for admin from 203.0.113.1 port 22441 ssh2"
echo "  Sent SSH brute force sequence"
sleep 3

# =============================================================================
# 2. SSH Invalid User Scan (triggers rule 11)
# =============================================================================
echo -e "${YLW}[2] SSH Invalid User Scan...${NC}"
for user in testuser1 testuser2 admin123 operator guest; do
    send_log "198.51.100.42" "$PARSER_AUTH" \
        "Invalid user ${user} from 198.51.100.42 port 54321 ssh2"
    sleep 0.3
done
echo "  Sent SSH invalid user scan"
sleep 3

# =============================================================================
# 3. Windows Brute Force (triggers rule 30 / 57)
# =============================================================================
echo -e "${YLW}[3] Windows Failed Logon Storm...${NC}"
for i in $(seq 1 20); do
    send_log "10.10.10.${i}" "$PARSER_SYSLOG" \
        "windows login_failed [security:4625] user=administrator from 10.10.10.${i}"
    sleep 0.1
done
echo "  Sent 20 Windows failed logons"
sleep 3

# =============================================================================
# 4. Windows Brute Force → Success (triggers rule 30)
# =============================================================================
echo -e "${YLW}[4] Windows Brute Force to Success...${NC}"
send_log "192.168.50.10" "$PARSER_SYSLOG" \
    "windows login_failed [security:4625] user=jdoe from 192.168.50.10"
sleep 1
send_log "192.168.50.10" "$PARSER_SYSLOG" \
    "windows login_failed [security:4625] user=jdoe from 192.168.50.10"
sleep 1
send_log "192.168.50.10" "$PARSER_SYSLOG" \
    "windows login_success [security:4624] user=jdoe from 192.168.50.10"
echo "  Sent Windows brute force sequence"
sleep 3

# =============================================================================
# 5. Malicious artifact detection — mimikatz, vssadmin
# =============================================================================
echo -e "${YLW}[5] Malicious Artifact Detection...${NC}"
send_log "10.0.0.55" "$PARSER_SYSLOG" \
    "process started: mimikatz.exe by user SYSTEM"
sleep 1
send_log "10.0.0.55" "$PARSER_SYSLOG" \
    "cmd.exe executed: vssadmin delete shadows /all /quiet"
sleep 1
send_log "10.0.0.77" "$PARSER_SYSLOG" \
    "powershell.exe -encodedcommand JABjAGwAaQBlAG4AdA"
echo "  Sent malicious artifact triggers"
sleep 3

# =============================================================================
# 6. Port scan detection (triggers rule 50 threshold)
# =============================================================================
echo -e "${YLW}[6] Port Scan — High Rate...${NC}"
for i in $(seq 1 35); do
    send_log "45.33.32.${i}" "$PARSER_SYSLOG" \
        "connection refused from 45.33.32.156 port $((1000 + i))"
    sleep 0.1
done
echo "  Sent 35 connection refused events"
sleep 3

# =============================================================================
# 7. Sudo escalation after SSH login (triggers rule 13)
# =============================================================================
echo -e "${YLW}[7] SSH Login → Sudo Escalation...${NC}"
send_log "172.16.0.99" "$PARSER_AUTH" \
    "Accepted password for deploy from 172.16.0.99 port 55123 ssh2"
sleep 2
send_log "172.16.0.99" "$PARSER_AUTH" \
    "sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash"
echo "  Sent SSH→sudo sequence"
sleep 3

# =============================================================================
# 8. Windows Privilege Escalation (triggers rule 31)
# =============================================================================
echo -e "${YLW}[8] Windows Privileged Logon After Standard Logon...${NC}"
send_log "10.20.30.40" "$PARSER_SYSLOG" \
    "windows login_success [security:4624] user=operator from 10.20.30.40"
sleep 2
send_log "10.20.30.40" "$PARSER_SYSLOG" \
    "windows privileged_logon [security:4672] user=operator from 10.20.30.40"
echo "  Sent Windows privilege escalation sequence"
sleep 3

# =============================================================================
# 9. Credential reuse across servers (triggers rule 70 - user grouping)
# =============================================================================
echo -e "${YLW}[9] Credential Reuse Across Servers (user grouping)...${NC}"
send_log "10.1.1.10" "$PARSER_AUTH" \
    "authentication failure user=alice from 10.1.1.10 port 22"
sleep 2
send_log "10.1.1.20" "$PARSER_AUTH" \
    "Accepted publickey for alice from 10.1.1.20 port 48721 ssh2"
echo "  Sent credential reuse sequence"
sleep 3

# =============================================================================
# 10. Distributed credential stuffing (triggers rule 90 - global)
# =============================================================================
echo -e "${YLW}[10] Distributed Credential Stuffing...${NC}"
for i in 1 2 3 4; do
    send_log "185.220.101.${i}" "$PARSER_AUTH" \
        "authentication failure user=webadmin from 185.220.101.${i} port 22"
    sleep 0.5
done
send_log "185.220.101.5" "$PARSER_AUTH" \
    "Accepted password for webadmin from 185.220.101.5 port 22 ssh2"
echo "  Sent distributed stuffing sequence"
sleep 5

# =============================================================================
# Results
# =============================================================================
echo ""
AFTER=$(count_alerts)
NEW=$((AFTER - BEFORE))
echo -e "${GRN}══════════════════════════════════════${NC}"
echo -e "${GRN}  Alert generation complete            ${NC}"
echo -e "${GRN}══════════════════════════════════════${NC}"
echo -e "  Alerts before : ${BEFORE}"
echo -e "  Alerts after  : ${AFTER}"
echo -e "  New alerts    : ${NEW}"
echo ""
echo "Recent alerts:"
psql -U opensiem -d museum -c "
SELECT id, alert_type, severity, source_ip,
       LEFT(admin_note, 60) AS case_name
FROM alerts
ORDER BY id DESC
LIMIT 15;" 2>/dev/null
echo ""
echo "Open Chronicler → Alerts to see them and test the escalation workflow."
