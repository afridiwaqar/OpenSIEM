#!/usr/bin/python3
# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024–present
# See LICENSE for details.
import time
import socket
import configparser
import signal
import os
# import getips
import os.path
import chardet
from datetime import datetime
import platform
import subprocess
import psutil
import xml.etree.ElementTree as ET
import threading
import logging
from queue import Queue
from urllib.request import urlopen
import re

# Set logging to DEBUG to see everything
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Watcher configuration
SERVER = str("127.0.1.1")
PORT = str(11514)
STATE_PORT = str(51780)
SOURCES = "/var/log/syslog,/var/log/auth.log,/var/log/apache2/access.log"
OFFSET_FILE = './offsets.txt'  # Path to the persistent storage file

logging.debug(f"Using offset file at: {os.path.abspath(OFFSET_FILE)}")

send_queue = Queue()

Client_name = "Developer-Laptop"

NO_OF_SOURCES = len(SOURCES.split(","))
SOURCES_LIST = SOURCES.split(",")

# List of services to monitor
services_to_monitor = ["rsyslog", "postgresql"]

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connect to Google's DNS server
        s.connect(('8.8.8.8', 53))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def check_service_status(service_name):
    try:
        result = subprocess.run(["systemctl", "is-active", service_name], capture_output=True, text=True)
        return result.stdout.strip() == "active"
    except Exception as e:
        print(f"Error checking status of {service_name}: {e}")
        return False

class StateHandler:
    FORMAT = "utf-8"
    ADDR = (SERVER, int(PORT))
    HEARTBEAT_INTERVAL = 30
    SOCKET_TIMEOUT = 10

    def __init__(self):
        self.client = None
        self.lock = threading.Lock()
        self.connected = False
        self.connect()

        t_sender = threading.Thread(target=self.sender_loop, daemon=True, name="SenderThread")
        t_sender.start()
        
        t = threading.Thread(target=self._heartbeat_loop, daemon=True, name="HeartbeatThread")
        t.start()

    def connect(self):
        logging.debug(f"Attempting to connect to {self.ADDR}")
        while True:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.settimeout(self.SOCKET_TIMEOUT)
                sock.connect(self.ADDR)

                with self.lock:
                    self.client = sock
                    self.connected = True

                logging.info(f"[CONNECTED] to {self.ADDR}")
                return

            except Exception as e:
                logging.warning(f"Connect failed: {e}, retrying in 5s")
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
                logging.debug("Heartbeat sent")
            except Exception:
                logging.warning("Heartbeat failed, reconnecting")
                self._reconnect()

    def sender_loop(self):
        while True:
            data = send_queue.get()
            logging.debug(f"Sender loop got {len(data)} bytes from queue")
            try:
                with self.lock:
                    if not self.connected:
                        raise RuntimeError("Not connected")
                    self._send_raw(data)
                logging.debug(f"Successfully sent {len(data)} bytes")
            except Exception as e:
                logging.warning(f"Send failed: {e}, reconnecting")
                self._reconnect()
                send_queue.put(data)  # retry
                time.sleep(1)

    def send_to_HQ(self, msg: str):
        if not msg:
            return

        try:
            data = msg.encode(self.FORMAT, errors="replace") + b"\n"
            send_queue.put(data, block=False)
            logging.debug(f"Queued message: {msg[:100]}...")  # Show first 100 chars

        except send_queue.Full:
            logging.error("Send queue full — dropping log")
        except Exception as e:
            logging.error(f"Queue error: {e}")


# Gather system statistics and return them as an XML string
def gather_system_stats(given_name):
    logging.debug("Gathering system stats...")
    system_id = platform.node()

    root = ET.Element("SystemStats")
    system_element = ET.SubElement(root, "System")
    system_element.set("ID", system_id)
    system_element.set("GivenName", given_name)

    # CPU Usage
    cpu_element = ET.SubElement(system_element, "CPUUsage")
    cpu_element.set("Total", f"{psutil.cpu_percent(interval=1)}%")
    for i, usage in enumerate(psutil.cpu_percent(interval=1, percpu=True)):
        core_element = ET.SubElement(cpu_element, f"Core{i}")
        core_element.text = f"{usage}%"

    # RAM Usage
    virtual_memory = psutil.virtual_memory()
    ram_element = ET.SubElement(system_element, "RAMUsage")
    ram_element.set("Total", f"{virtual_memory.total / (1024**3):.2f} GB")
    ram_element.set("Available", f"{virtual_memory.available / (1024**3):.2f} GB")
    ram_element.set("Used", f"{virtual_memory.used / (1024**3):.2f} GB")
    ram_element.set("Percentage", f"{virtual_memory.percent}%")

    # Disk Usage
    disk_usage = psutil.disk_usage('/')
    disk_element = ET.SubElement(system_element, "DiskUsage")
    disk_element.set("Total", f"{disk_usage.total / (1024**3):.2f} GB")
    disk_element.set("Used", f"{disk_usage.used / (1024**3):.2f} GB")
    disk_element.set("Free", f"{disk_usage.free / (1024**3):.2f} GB")
    disk_element.set("Percentage", f"{disk_usage.percent}%")

    # Service Status
    services_element = ET.SubElement(system_element, "ServiceStatus")
    for service in services_to_monitor:
        service_element = ET.SubElement(services_element, "Service")
        service_element.set("Name", service)
        service_status = "Running" if check_service_status(service) else "Stopped"
        service_element.set("Status", service_status)

    xml_string = ET.tostring(root, encoding='unicode')
    logging.debug(f"Generated XML stats: {len(xml_string)} bytes")
    logging.debug(f"XML preview: {xml_string[:200]}...")
    return xml_string

def send_system_stats(xml_data):
    """
    Send system statistics to the stats server on 127.0.0.1:51780
    """
    logging.debug(f"Attempting to send stats to {SERVER}:{STATE_PORT}")
    logging.debug(f"XML data size: {len(xml_data)} bytes")

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(5)  # Set timeout to 5 seconds
        
        logging.debug(f"Socket created, attempting connection...")
        try:
            client_socket.connect((SERVER, int(STATE_PORT)))
            logging.debug(f"Connected to stats server {SERVER}:{STATE_PORT}")
            
            # Send the system stats XML to the server
            bytes_sent = client_socket.sendall(xml_data.encode('utf-8'))
            logging.info(f"System stats sent to {SERVER}:{STATE_PORT} ({len(xml_data)} bytes)")
            return True
            
        except socket.timeout:
            logging.warning(f"Timeout connecting to stats server {SERVER}:{STATE_PORT}")
            return False
        except ConnectionRefusedError:
            logging.warning(f"Connection refused: Stats server {SERVER}:{STATE_PORT} not available or not listening")
            return False
        except Exception as e:
            logging.error(f"Error sending stats: {e}", exc_info=True)
            return False
            
    except Exception as e:
        logging.error(f"Error creating socket for stats: {e}", exc_info=True)
        return False
    finally:
        try:
            client_socket.close()
            logging.debug("Stats socket closed")
        except Exception as e:
            logging.debug(f"Error closing stats socket: {e}")

def read_offsets():
    offsets = {}
    logging.debug("Reading offsets...")

    if os.path.exists(OFFSET_FILE):
        with open(OFFSET_FILE, 'r') as f:
            for line in f:
                try:
                    file, timestamp, line_number = line.strip().split(':')
                    offsets[file] = (float(timestamp), int(line_number))
                except ValueError:
                    logging.debug(f"Ignoring invalid line in offsets file: {line}")
    else:
        logging.debug(f"Offset file does not exist: {OFFSET_FILE}")
    logging.debug(f"Loaded offsets: {offsets}")
    return offsets

def write_offsets(offsets):
    logging.debug(f"Writing offsets: {offsets}")
    with open(OFFSET_FILE, 'w') as f:
        for file, (timestamp, line_number) in offsets.items():
            f.write(f"{file}:{timestamp}:{line_number}\n")
    logging.debug("Offsets written successfully")

def watch_logs(handler: StateHandler):
    offsets = read_offsets()

    logging.info(f"Starting to watch logs at {datetime.now()}")
    logging.debug(f"Initial offsets: {offsets}")

    while True:
        for source in SOURCES_LIST:
            if os.path.exists(source):
                try:
                    current_timestamp = os.path.getmtime(source)
                    last_timestamp, last_line_number = offsets.get(source, (0.0, 0))

                    logging.debug(f"Checking {source}")

                    with open(source, 'rb') as f:
                        f.seek(0, 2)  # Move to the end of the file
                        file_size = f.tell()

                        if file_size < last_line_number:
                            logging.debug(f"File {source} seems to have been truncated. Starting from beginning.")
                            f.seek(0)
                            last_line_number = 0
                        else:
                            f.seek(last_line_number)

                        chunk_size = 1024 * 1024  # 1 MB chunks
                        new_content = f.read(chunk_size)
                        if new_content:
                            logging.debug(f"New content found in {source}. Size: {len(new_content)} bytes")
                            result = chardet.detect(new_content)
                            encoding = result['encoding'] or 'utf-8'

                            try:
                                lines = new_content.decode(encoding).splitlines()
                            except UnicodeDecodeError:
                                lines = new_content.decode('latin-1').splitlines()

                            for line in lines:
                                line = line.strip()
                                if line:
                                    log_with_source = f"{get_local_ip()} {source} {line}"
                                    handler.send_to_HQ(log_with_source)

                            last_line_number = f.tell()
                            offsets[source] = (current_timestamp, last_line_number)
                            logging.debug(f"Updated offset for {source}: {offsets[source]}")
                        else:
                            logging.debug(f"No new logs in {source}.")

                except PermissionError as e:
                    logging.error(f"Permission error for {source}: {e}")
                except Exception as e:
                    logging.error(f"Error processing file {source}: {str(e)}", exc_info=True)
            else:
                logging.warning(f"Log file does not exist: {source}")

        write_offsets(offsets)
        time.sleep(0.1)


def send_stats_periodically():
    """Send system stats every 10 seconds"""
    logging.info("Starting stats periodic sender")
    while True:
        try:
            logging.debug("Starting stats collection cycle")
            xml_data = gather_system_stats(Client_name)
            success = send_system_stats(xml_data)
            if success:
                logging.info("Stats sent successfully")
            else:
                logging.warning("Failed to send stats")
        except Exception as e:
            logging.error(f"Error in stats gathering/sending: {e}", exc_info=True)
        logging.debug("Sleeping for 10 seconds before next stats send")
        time.sleep(10)


if __name__ == "__main__":
    logging.info("Starting watcher application")
    
    # Log network information
    try:
        import netifaces
        logging.debug(f"Local IP addresses: {get_local_ip()}")
    except:
        pass
    
    handler = StateHandler()

    # Start log watching thread
    log_thread = threading.Thread(target=watch_logs, args=(handler,), daemon=True, name="LogThread")
    log_thread.start()

    # Start stats sending thread
    stats_thread = threading.Thread(target=send_stats_periodically, daemon=True, name="StatsThread")
    stats_thread.start()

    # Keep main thread alive
    logging.info("All threads started. Press Ctrl+C to exit.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Shutting down...")
