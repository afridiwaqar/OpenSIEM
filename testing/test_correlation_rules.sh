#!/bin/bash
# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024–present
# See LICENSE for details.
# =============================================================================
# OpenSIEM Atom v1 — Correlation Rule Test Suite
#
# Usage:
#   chmod +x test_correlation_rules.sh
#   ./test_correlation_rules.sh            # run all rules
#   ./test_correlation_rules.sh 10         # run only rule 10
#   ./test_correlation_rules.sh 10 13 15   # run specific rules
#
# DELAY = seconds between each logger call. Increase if your watcher poll
# interval is slower than 2 seconds.
# =============================================================================

DELAY=2

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
BLU='\033[0;34m'; CYN='\033[0;36m'; NC='\033[0m'

send() { logger "$1"; echo -e "  ${CYN}→ logger:${NC} $1"; sleep "$DELAY"; }
hdr()  {
    echo -e "\n${YLW}══════════════════════════════════════════${NC}"
    echo -e "${YLW}  Rule $1 — $2${NC}"
    echo -e "${YLW}══════════════════════════════════════════${NC}"
}
pass() { echo -e "${GRN}  ✓ Messages sent — watch the Alerts page${NC}\n"; }

# ── Rule 10 ──────────────────────────────────────────────────────────────────
run_10() {
    hdr 10 "SSH Brute Force to Successful Login"
    send "SSH login failed: user=root method=password from=192.168.1.99:54321"
    send "SSH login accepted: user=root method=password from=192.168.1.99:54321"
    pass
}

# ── Rule 11 ──────────────────────────────────────────────────────────────────
run_11() {
    hdr 11 "SSH Invalid User Scan"
    send "SSH invalid user: user=admin from=10.0.0.55:51234"
    send "SSH invalid user: user=administrator from=10.0.0.55:51235"
    pass
}

# ── Rule 12 ──────────────────────────────────────────────────────────────────
run_12() {
    hdr 12 "Firewall Block with Continued SSH Attempt"
    send "UFW BLOCK IN=eth0 SRC=172.16.5.20 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22"
    send "SSH login failed: user=root method=password from=172.16.5.20:54321"
    pass
}

# ── Rule 13 ──────────────────────────────────────────────────────────────────
run_13() {
    hdr 13 "SSH Login followed by Sudo Escalation"
    send "SSH login accepted: user=waqar method=publickey from=192.168.1.10:54321"
    send "sudo: waqar : TTY=pts/0 ; PWD=/home/waqar ; USER=root ; COMMAND=/bin/bash"
    pass
}

# ── Rule 14 ──────────────────────────────────────────────────────────────────
run_14() {
    hdr 14 "Database Auth Failure with Web Probe"
    send "PostgreSQL auth failure for user 'hacker' from 10.10.10.5"
    send "10.10.10.5 - - [21/Mar/2026:17:00:00 +0500] \"GET /phpmyadmin HTTP/1.1\" 404 512"
    pass
}

# ── Rule 15 ──────────────────────────────────────────────────────────────────
run_15() {
    hdr 15 "Web Directory Scanner Detected"
    send "10.9.9.9 - - [21/Mar/2026:17:00:01 +0500] \"GET /.env HTTP/1.1\" 404 162"
    send "10.9.9.9 - - [21/Mar/2026:17:00:02 +0500] \"GET /wp-admin HTTP/1.1\" 404 162"
    pass
}

# ── Rule 16 ──────────────────────────────────────────────────────────────────
run_16() {
    hdr 16 "AppArmor Denial with OOM Kill"
    send "AppArmor DENIED op=open profile=snap.firefox name=/proc/mem pid=1234 comm=app"
    send "OOM killer killed PID 9876 (firefox) score 500"
    pass
}

# ── Rule 17 ──────────────────────────────────────────────────────────────────
run_17() {
    hdr 17 "MySQL Auth Failure with Web Request"
    send "password authentication failed for user 'wp_user' from host 192.168.2.30"
    send "192.168.2.30 - - [21/Mar/2026:17:00:05 +0500] \"POST /wp-login.php HTTP/1.1\" 200 4821"
    pass
}

# ── Rule 18 ──────────────────────────────────────────────────────────────────
run_18() {
    hdr 18 "Suspicious Cron Job with Outbound Block"
    send "Cron job: user=www-data cmd=/tmp/update.sh"
    send "UFW BLOCK IN= OUT=eth0 SRC=192.168.1.5 DST=45.33.32.156 PROTO=TCP SPT=49200 DPT=4444"
    pass
}

# ── Rule 19 ──────────────────────────────────────────────────────────────────
run_19() {
    hdr 19 "Multi-Service Credential Stuffing"
    send "SSH login failed: user=admin method=password from=185.220.101.5:61234"
    send "185.220.101.5 - - [21/Mar/2026:17:00:10 +0500] \"GET /admin HTTP/1.1\" 401 512"
    pass
}

# ── Rule 20 ──────────────────────────────────────────────────────────────────
run_20() {
    hdr 20 "Audit Syscall After SSH Login (Post-Exploitation)"
    send "SSH login accepted: user=deploy method=publickey from=10.0.5.100:22"
    send "AUDIT SYSCALL 59 success=yes pid=5678 uid=1000 comm=bash exe=/bin/bash"
    pass
}

# ── Rule 21 ──────────────────────────────────────────────────────────────────
run_21() {
    hdr 21 "Web 500 Errors with Database Error"
    send "10.1.1.1 - - [21/Mar/2026:17:00:15 +0500] \"POST /api/login HTTP/1.1\" 500 89"
    send "POSTGRESQL ERROR: syntax error at or near DROP at character 1"
    pass
}

# ── Rule 22 ──────────────────────────────────────────────────────────────────
run_22() {
    hdr 22 "Repeated SELinux AVC Denial"
    send "SELinux AVC DENIED: {read write} on file stype=httpd_t ttype=shadow_t comm=httpd"
    send "SELinux AVC DENIED: {open} on file stype=httpd_t ttype=etc_t comm=httpd"
    pass
}

# ── Original use cases (regression) ──────────────────────────────────────────
run_ddos() {
    hdr "1 (original)" "DDOS / Brute Force"
    send "Attempting To login with default username and password"
    send "Attempt failed."
    send "Brute forcing Password."
    send "Brute forcing Password."
    send "Brute forcing Password."
    send "Password cracked."
    send "Entering System"
    pass
}

run_apt() {
    hdr "2 (original)" "APT Test"
    send "Identifying System"
    send "Identifying Location"
    send "deploying Payload"
    send "deploying Payload"
    send "Establishing CnC"
    pass
}

# =============================================================================
ALL_RULES=(10 11 12 13 14 15 16 17 18 19 20 21 22 ddos apt)

run_rule() {
    case "$1" in
        10)   run_10   ;;
        11)   run_11   ;;
        12)   run_12   ;;
        13)   run_13   ;;
        14)   run_14   ;;
        15)   run_15   ;;
        16)   run_16   ;;
        17)   run_17   ;;
        18)   run_18   ;;
        19)   run_19   ;;
        20)   run_20   ;;
        21)   run_21   ;;
        22)   run_22   ;;
        ddos) run_ddos ;;
        apt)  run_apt  ;;
        *)    echo -e "${RED}Unknown rule: $1${NC}"; exit 1 ;;
    esac
}

# =============================================================================
echo -e "${BLU}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  OpenSIEM Atom v1 — Rule Test Suite      ║"
echo "  ║  Delay between messages: ${DELAY}s              ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${NC}"

if [[ $# -eq 0 ]]; then
    echo -e "${YLW}Running all ${#ALL_RULES[@]} rule sets...${NC}"
    for rule in "${ALL_RULES[@]}"; do
        run_rule "$rule"
    done
else
    for rule in "$@"; do
        run_rule "$rule"
    done
fi

echo -e "${GRN}══════════════════════════════════════════${NC}"
echo -e "${GRN}  All tests sent. Check the Alerts page.${NC}"
echo -e "${GRN}══════════════════════════════════════════${NC}\n"
