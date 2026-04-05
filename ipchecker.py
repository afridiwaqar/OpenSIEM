#!/usr/bin/python3

# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024–present
# See LICENSE for details.

import ipaddress
import re
import sys
import socket

def load_blacklist():
    ip_set = set()
    with open('blackip.txt', 'r') as f:
        for line in f:
            ip = line.strip()
            try:
                ipaddress.ip_address(ip)
                ip_set.add(ip)
            except ValueError:
                print(f'Invalid IP address in blacklist: {ip}')
    print(f"Loaded {len(ip_set)} blacklisted IPs")
    return ip_set

BLACKLISTED_IPS = load_blacklist()

def check_ip(log_message):
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    
    ips_in_log = re.findall(ip_pattern, log_message)
    
    for ip in ips_in_log:
        if ip in BLACKLISTED_IPS:
            print(f"\n\033[1;31m ALERT: Blacklisted IP detected: {ip} \033[0m")
            return True
    
    return False

if __name__ == "__main__":
    sample_log = "Connection attempt from 192.168.1.100 to 10.0.0.1 failed"
    result = check_ip(sample_log)
    if result:
        print("\n\033[1;31m Blacklisted IP detected in the log message.")
    else:
        print("No blacklisted IPs found in the log message.")
