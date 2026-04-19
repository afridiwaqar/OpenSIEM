#!/usr/bin/env python3
# OpenSIEM Windows Watcher Agent
# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024-present
# See LICENSE for details.
#
# Requires:  pip install pywin32 psutil
# Run as:    Administrator (required for Security channel)
#            or a user in the "Event Log Readers" group (Application/System only)
#
# To install as a Windows service, see README_WINDOWS_WATCHER.md

import time
import socket
import os
import json
import platform
import threading
import logging
import xml.etree.ElementTree as ET
from queue import Queue, Full
from datetime import datetime

# =============================================================================
# ADMINISTRATOR CONFIGURATION — edit this section before deploying
# =============================================================================

SERVER     = "192.168.1.10"   # IP address of the OpenSIEM server
PORT       = 11514             # OpenSIEM TCP ingestion port
STATE_PORT = 51780             # OpenSIEM stats/heartbeat port

CLIENT_NAME = "Windows-Workstation-01"   # Human-readable name shown in Chronicler

# Path to store the bookmark file (tracks which events have been sent).
# The watcher resumes from this point after a restart or network outage.
# Must be a directory the watcher process has write access to.
BOOKMARK_FILE = r"C:\ProgramData\OpenSIEM\evtlog_bookmarks.json"

# Event channels to monitor.
# Format:  "Channel Name": [list of Event IDs to forward]
# Leave the list EMPTY to forward ALL events from that channel.
#
# Common channel names:
#   "Security"      - Logons, policy changes, privilege use, account management
#   "System"        - Service installs, driver errors, shutdowns, reboots
#   "Application"   - Application crashes, errors, custom app events
#   "Setup"         - Windows Update and component installation
#
# Example with filtering:
#   "Security": [4624, 4625, 4634, 4648, 4688, 4720, 4726, 4740]
#   "System":   [7045, 7040, 1074, 6005, 6006]
#
# Example forwarding everything from Security and System:
#   "Security": []
#   "System":   []
#
CHANNELS = {
    "Security": [
        4624,   # Successful logon
        4625,   # Failed logon
        4634,   # Logoff
        4647,   # User-initiated logoff
        4648,   # Logon using explicit credentials (runas)
        4672,   # Special privileges assigned at logon (admin logon)
        4688,   # New process created
        4689,   # Process exited
        4698,   # Scheduled task created
        4699,   # Scheduled task deleted
        4700,   # Scheduled task enabled
        4701,   # Scheduled task disabled
        4720,   # User account created
        4722,   # User account enabled
        4723,   # Password change attempt
        4724,   # Password reset attempt
        4725,   # User account disabled
        4726,   # User account deleted
        4728,   # Member added to security-enabled global group
        4732,   # Member added to security-enabled local group
        4738,   # User account changed
        4740,   # User account locked out
        4756,   # Member added to security-enabled universal group
        4768,   # Kerberos TGT requested (domain logon attempt)
        4769,   # Kerberos service ticket requested
        4771,   # Kerberos pre-authentication failed (bad password)
        4776,   # NTLM authentication attempt
        4798,   # User's local group membership enumerated
        4799,   # Security-enabled local group membership enumerated
        5140,   # Network share accessed
        5145,   # Network share object access check
    ],
    "System": [
        7045,   # New service installed
        7040,   # Service start type changed
        7034,   # Service crashed unexpectedly
        7036,   # Service started or stopped
        1074,   # System shutdown or restart initiated
        6005,   # Event log service started (system boot)
        6006,   # Event log service stopped (clean shutdown)
        6008,   # Unexpected shutdown (previous dirty shutdown)
    ],
    "Application": [
        1000,   # Application error/crash
        1001,   # Windows Error Reporting (crash details)
        1002,   # Application hang
    ],
}

# Windows services to include in the stats heartbeat sent to Chronicler.
# Use the exact service short name (sc query <name> or services.msc).
SERVICES_TO_MONITOR = [
    "W32Time",       # Windows Time
    "WinDefend",     # Windows Defender
    "EventLog",      # Windows Event Log (if this is stopped, we have a problem)
]

# How often (seconds) to poll each channel for new events.
# Lower = more real-time but more CPU. 1–5 seconds is a good range.
POLL_INTERVAL = 2

# How often (seconds) to send system stats to the OpenSIEM stats port.
STATS_INTERVAL = 30

# =============================================================================
# END OF ADMINISTRATOR CONFIGURATION
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(threadName)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(
            os.path.join(os.path.dirname(BOOKMARK_FILE), "watcher_windows.log"),
            encoding="utf-8"
        ) if os.path.isdir(os.path.dirname(BOOKMARK_FILE)) else logging.StreamHandler()
    ]
)

send_queue = Queue(maxsize=50000)

_local_ip_cache = None
_local_ip_lock  = threading.Lock()


def get_local_ip():
    global _local_ip_cache
    with _local_ip_lock:
        if _local_ip_cache:
            return _local_ip_cache
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 53))
            _local_ip_cache = s.getsockname()[0]
        except Exception:
            _local_ip_cache = "127.0.0.1"
        finally:
            s.close()
        return _local_ip_cache


def _ensure_bookmark_dir():
    d = os.path.dirname(BOOKMARK_FILE)
    if d and not os.path.exists(d):
        try:
            os.makedirs(d, exist_ok=True)
        except Exception as e:
            logging.error(f"Cannot create bookmark directory {d}: {e}")


def load_bookmarks():
    _ensure_bookmark_dir()
    if not os.path.exists(BOOKMARK_FILE):
        return {}
    try:
        with open(BOOKMARK_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logging.warning(f"Could not read bookmark file: {e} — starting from current position")
        return {}

def save_bookmarks(bookmarks: dict):
    _ensure_bookmark_dir()
    tmp = BOOKMARK_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(bookmarks, f, indent=2)
        os.replace(tmp, BOOKMARK_FILE)
    except Exception as e:
        logging.error(f"Failed to write bookmarks: {e}")


class StateHandler:
    FORMAT           = "utf-8"
    HEARTBEAT_INTERVAL = 30
    SOCKET_TIMEOUT   = 10

    def __init__(self):
        self.client    = None
        self.lock      = threading.Lock()
        self.connected = False
        self._addr     = (SERVER, PORT)
        self.connect()

        threading.Thread(target=self.sender_loop,    daemon=True, name="SenderThread").start()
        threading.Thread(target=self._heartbeat_loop, daemon=True, name="HeartbeatThread").start()

    def connect(self):
        logging.info(f"Connecting to OpenSIEM server {self._addr} ...")
        while True:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.settimeout(self.SOCKET_TIMEOUT)
                sock.connect(self._addr)
                with self.lock:
                    self.client    = sock
                    self.connected = True
                logging.info(f"Connected to {self._addr}")
                return
            except Exception as e:
                logging.warning(f"Connection failed: {e} — retrying in 5 s")
                time.sleep(5)

    def _send_raw(self, data: bytes):
        if not self.connected:
            raise RuntimeError("Not connected")
        self.client.sendall(data)

    def _reconnect(self):
        with self.lock:
            try:
                self.client.close()
            except Exception:
                pass
            self.connected = False
        self.connect()

    def _heartbeat_loop(self):
        while True:
            time.sleep(self.HEARTBEAT_INTERVAL)
            try:
                self._send_raw(b"__HEARTBEAT__\n")
            except Exception:
                logging.warning("Heartbeat failed — reconnecting")
                self._reconnect()

    def sender_loop(self):
        while True:
            data = send_queue.get()
            try:
                with self.lock:
                    if not self.connected:
                        raise RuntimeError("Not connected")
                    self._send_raw(data)
            except Exception as e:
                logging.warning(f"Send failed: {e} — will retry")
                self._reconnect()
                send_queue.put(data)
                time.sleep(1)

    def send_to_HQ(self, msg: str):
        if not msg:
            return
        try:
            data = msg.encode(self.FORMAT, errors="replace") + b"\n"
            send_queue.put(data, block=True, timeout=5)
        except Full:
            logging.error("Send queue full — event dropped")
        except Exception as e:
            logging.error(f"Queue error: {e}")

def _check_service_status(name: str) -> str:
    try:
        import win32serviceutil
        status = win32serviceutil.QueryServiceStatus(name)
        # status[1] == 4 means SERVICE_RUNNING
        return "Running" if status[1] == 4 else "Stopped"
    except Exception:
        return "Unknown"

def gather_system_stats():
    try:
        import psutil
    except ImportError:
        return "<SystemStats/>"

    root    = ET.Element("SystemStats")
    sys_el  = ET.SubElement(root, "System")
    sys_el.set("ID",        platform.node())
    sys_el.set("GivenName", CLIENT_NAME)
    sys_el.set("OS",        platform.version())

    cpu_el = ET.SubElement(sys_el, "CPUUsage")
    cpu_el.set("Total", f"{psutil.cpu_percent(interval=1)}%")

    vm      = psutil.virtual_memory()
    ram_el  = ET.SubElement(sys_el, "RAMUsage")
    ram_el.set("Total",      f"{vm.total      / (1024**3):.2f} GB")
    ram_el.set("Used",       f"{vm.used       / (1024**3):.2f} GB")
    ram_el.set("Available",  f"{vm.available  / (1024**3):.2f} GB")
    ram_el.set("Percentage", f"{vm.percent}%")

    try:
        du     = psutil.disk_usage("C:\\")
        dsk_el = ET.SubElement(sys_el, "DiskUsage")
        dsk_el.set("Total",      f"{du.total / (1024**3):.2f} GB")
        dsk_el.set("Used",       f"{du.used  / (1024**3):.2f} GB")
        dsk_el.set("Free",       f"{du.free  / (1024**3):.2f} GB")
        dsk_el.set("Percentage", f"{du.percent}%")
    except Exception:
        pass

    svc_el = ET.SubElement(sys_el, "ServiceStatus")
    for svc in SERVICES_TO_MONITOR:
        s = ET.SubElement(svc_el, "Service")
        s.set("Name",   svc)
        s.set("Status", _check_service_status(svc))

    return ET.tostring(root, encoding="unicode")

def send_system_stats(xml_data: str):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((SERVER, STATE_PORT))
        sock.sendall(xml_data.encode("utf-8"))
        sock.close()
    except Exception as e:
        logging.warning(f"Stats send failed: {e}")

def stats_loop():
    logging.info("Stats sender started")
    while True:
        try:
            xml = gather_system_stats()
            send_system_stats(xml)
        except Exception as e:
            logging.error(f"Stats error: {e}")
        time.sleep(STATS_INTERVAL)

def _format_event(channel: str, event_id: int, record_number: int,
                  time_generated: str, source: str, message: str,
                  user: str, computer: str) -> str:

    msg_clean = message.replace("\r", " ").replace("\n", " ").strip()
    msg_clean = " ".join(msg_clean.split())
    return (
        f"WinEvt channel={channel} event_id={event_id} "
        f"record={record_number} time={time_generated} "
        f"source={source!r} user={user!r} computer={computer!r} "
        f"msg={msg_clean!r}"
    )

def _read_channel(channel: str, allowed_ids: list, bookmarks: dict, handler: StateHandler):
    try:
        import win32evtlog
        import win32evtlogutil
        import win32con
        import pywintypes
    except ImportError:
        logging.error("pywin32 is not installed. Run: pip install pywin32")
        return

    filter_ids = set(allowed_ids) if allowed_ids else None
    last_record = bookmarks.get(channel, 0)
    ip = get_local_ip()

    # The parser path tells messagehandler.py which module to use.
    parser_path = "modules/parse_windows_evtlog.py"

    try:
        log_handle = win32evtlog.OpenEventLog(None, channel)
    except Exception as e:
        logging.error(f"Cannot open channel '{channel}': {e}")
        return

    try:
        flags     = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
        seq_flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        total = win32evtlog.GetNumberOfEventLogRecords(log_handle)
        if total == 0:
            win32evtlog.CloseEventLog(log_handle)
            return

        if last_record == 0:
            # First run — start from the current tail so we don't flood the
            # server with the entire event log history on first start.
            oldest = win32evtlog.GetOldestEventLogRecord(log_handle)
            bookmarks[channel] = max(0, oldest + total - 1)
            win32evtlog.CloseEventLog(log_handle)
            logging.info(f"[{channel}] First run — bookmarked at record {bookmarks[channel]}")
            return

        new_last = last_record

        while True:
            try:
                if last_record > 0:
                    events = win32evtlog.ReadEventLog(log_handle, flags, last_record + 1)
                else:
                    events = win32evtlog.ReadEventLog(log_handle, seq_flags, 0)
            except pywintypes.error as e:
                if e.winerror == 87:
                    # ERROR_INVALID_PARAMETER — record no longer in log (log wrapped).
                    # Reset to oldest available record.
                    logging.warning(f"[{channel}] Log wrapped — resetting bookmark")
                    oldest = win32evtlog.GetOldestEventLogRecord(log_handle)
                    bookmarks[channel] = oldest - 1
                    last_record        = bookmarks[channel]
                    new_last           = last_record
                    continue
                break

            if not events:
                break

            for ev in events:
                eid    = ev.EventID & 0xFFFF
                recnum = ev.RecordNumber

                if filter_ids and eid not in filter_ids:
                    new_last = max(new_last, recnum)
                    continue

                try:
                    msg = win32evtlogutil.SafeFormatMessage(ev, channel)
                except Exception:
                    msg = "(message unavailable)"

                try:
                    sid   = ev.Sid
                    user  = win32evtlogutil.GetUserName(sid) if sid else "N/A"
                except Exception:
                    user = "N/A"

                ts = ev.TimeGenerated.Format("%Y-%m-%dT%H:%M:%S")

                line = _format_event(
                    channel     = channel,
                    event_id    = eid,
                    record_number = recnum,
                    time_generated = ts,
                    source      = ev.SourceName,
                    message     = msg,
                    user        = user,
                    computer    = ev.ComputerName,
                )

                wire_msg = f"{ip} {parser_path} {line}"
                handler.send_to_HQ(wire_msg)
                new_last = max(new_last, recnum)

            last_record = new_last

        bookmarks[channel] = new_last

    except Exception as e:
        logging.error(f"[{channel}] Unexpected error: {e}", exc_info=True)
    finally:
        try:
            win32evtlog.CloseEventLog(log_handle)
        except Exception:
            pass


def watch_event_logs(handler: StateHandler):
    bookmarks = load_bookmarks()
    logging.info(f"Event log watcher started. Monitoring {len(CHANNELS)} channel(s): {list(CHANNELS.keys())}")

    while True:
        for channel, event_ids in CHANNELS.items():
            try:
                _read_channel(channel, event_ids, bookmarks, handler)
            except Exception as e:
                logging.error(f"[{channel}] Poll error: {e}", exc_info=True)

        save_bookmarks(bookmarks)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    logging.info("=" * 60)
    logging.info("OpenSIEM Windows Watcher starting")
    logging.info(f"  Client name : {CLIENT_NAME}")
    logging.info(f"  Server      : {SERVER}:{PORT}")
    logging.info(f"  Channels    : {list(CHANNELS.keys())}")
    logging.info(f"  Bookmark    : {BOOKMARK_FILE}")
    logging.info("=" * 60)

    try:
        import win32evtlog
    except ImportError:
        logging.critical("pywin32 is not installed. Run:  pip install pywin32")
        raise SystemExit(1)

    handler = StateHandler()

    evtlog_thread = threading.Thread(
        target=watch_event_logs, args=(handler,), daemon=True, name="EvtLogThread"
    )
    evtlog_thread.start()

    stats_thread = threading.Thread(
        target=stats_loop, daemon=True, name="StatsThread"
    )
    stats_thread.start()

    logging.info("All threads running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Shutting down.")
