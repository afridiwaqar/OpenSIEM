# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024–present
# See LICENSE for details.

import time
import os
import tempfile
import shutil
import threading
from collections import defaultdict
from datetime import datetime
import xml.etree.ElementTree as ET

_stats_lock = threading.Lock()

_STATS = {
    "start_time": time.time(),
    "total_messages": 0,
    "total_bytes": 0,
    "per_client": defaultdict(lambda: {
        "messages": 0,
        "bytes": 0
    })
}

STATS_DIR = "/etc/opensiem/stats"
os.makedirs(STATS_DIR, exist_ok=True)
os.chmod(STATS_DIR, 0o755)

def record_message(addr, byte_count):
    with _stats_lock:
        _STATS["total_messages"] += 1
        _STATS["total_bytes"] += byte_count
        _STATS["per_client"][addr]["messages"] += 1
        _STATS["per_client"][addr]["bytes"] += byte_count


def get_client_stats(addr):
    with _stats_lock:
        return dict(_STATS["per_client"].get(addr, {}))


def start():
    t = threading.Thread(
        target=_xml_writer_loop,
        daemon=True
    )
    t.start()

def _xml_writer_loop(interval=60):
    prev_messages = 0
    prev_bytes = 0

    while True:
        time.sleep(interval)

        with _stats_lock:
            now = time.time()
            uptime = int(now - _STATS["start_time"])
            total_msgs = _STATS["total_messages"]
            total_bytes = _STATS["total_bytes"]
            clients = dict(_STATS["per_client"])

        root = ET.Element("SocketStats")
        ET.SubElement(root, "StartTime").text = datetime.fromtimestamp(
            _STATS["start_time"]
        ).isoformat()
        ET.SubElement(root, "TotalMessages").text = str(total_msgs)
        ET.SubElement(root, "TotalBytes").text = str(total_bytes)
        ET.SubElement(root, "UptimeSeconds").text = str(uptime)

        _atomic_write(root, "socket_global.xml")

        msg_diff = total_msgs - prev_messages
        byte_diff = total_bytes - prev_bytes

        prev_messages = total_msgs
        prev_bytes = total_bytes

        rates = ET.Element("SocketRates")
        ET.SubElement(rates, "MessagesPerMinute").text = f"{msg_diff:.2f}"
        ET.SubElement(rates, "BytesPerSecond").text = f"{byte_diff / interval:.2f}"
        ET.SubElement(rates, "LastUpdated").text = datetime.now().isoformat()

        _atomic_write(rates, "socket_rates.xml")

        clients_root = ET.Element("Clients")

        for addr, data in clients.items():
            c = ET.SubElement(clients_root, "Client")
            ET.SubElement(c, "Address").text = f"{addr[0]}:{addr[1]}"
            ET.SubElement(c, "Messages").text = str(data["messages"])
            ET.SubElement(c, "Bytes").text = str(data["bytes"])

        _atomic_write(clients_root, "socket_clients.xml")


def _atomic_write(root, filename):
    tree = ET.ElementTree(root)
    dest = os.path.join(STATS_DIR, filename)

    with tempfile.NamedTemporaryFile(
        mode="w",
        delete=False,
        dir=STATS_DIR
    ) as tmp:
        tree.write(tmp.name, encoding="unicode")
        tmp_name = tmp.name
        
    os.chmod(tmp_name, 0o644)
    shutil.move(tmp_name, dest)
