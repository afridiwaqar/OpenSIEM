#!/usr/bin/env python3
# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024–present
# See LICENSE for details.

import os
import sys
sys.path.append('/home/waqar/OpenSIEM/chronicler')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'opensiem.settings')

import django
django.setup()

from dashboard.utils.xml_parser import stats_parser

print("Testing XML parsing...")
print(f"XML directory: {stats_parser.xml_dir}")

print("\n1. Testing ClientStats.xml:")
client_stats = stats_parser.parse_client_stats()
print(f"   Found {len(client_stats)} systems")
for system in client_stats:
    print(f"   - {system.get('name', 'Unknown')}: CPU {system.get('cpu', 0)}%")

print("\n2. Testing socket stats:")
socket_stats = stats_parser.parse_socket_stats()
print(f"   Bytes/sec: {socket_stats.get('rates', {}).get('bytes_per_second', 0)}")
print(f"   Messages/min: {socket_stats.get('rates', {}).get('messages_per_minute', 0)}")
print(f"   Total messages: {socket_stats.get('global', {}).get('total_messages', 0)}")

import os
print("\n3. Checking if files exist:")
files = ['ClientStats.xml', 'socket_global.xml', 'socket_rates.xml', 'socket_clients.xml']
for file in files:
    path = os.path.join(stats_parser.xml_dir, file)
    exists = os.path.exists(path)
    print(f"   {file}: {'✓' if exists else '✗'} ({path})")
    if exists:
        print(f"     Size: {os.path.getsize(path)} bytes")
