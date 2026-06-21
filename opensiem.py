#!/usr/bin/python3

# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024–present
# See LICENSE for details.

'''
TODO:

Port Reuse --> Added (Done)
Grace full Release of Port when hit ctrl + c (done, but not properly)
Parsing The Log File (Done)
Get Data from Port (Done)
Add another log source and Identity the Log Source (Done)
Have automatically select the Log Regular Expression based on the Log Source (Done)
Parsed Line to PostgreSQL or MySql (Done)
Corelation, The Big Shit (Done)
Sending system information from watchers (Done)
Make it modeuler, every regular expression in its own module. (Done)
Black Listed IP address dectection (done for Apache, make it global, Done)
Connection with multiple watchers (Done)
Artifacts needs to be pulled (from online datasets) and populated in database periodicly (Done)
A proper method is needed for alams (Done)
Raw Log Line goes to NoSQL (Will think about it if needed or not)
Web UI (Done)
TLS Encryption (Done)
'''

import banner

import os
import sys
import ssl
import socket
import threading
import signal
import importlib
import logging
import subprocess
import configparser
from collections import defaultdict
from threading import Lock

import collector
import serverstate
from tcphandler import tcp_handle_client
from malicious_keywords_manager import KeywordUpdater
from archiver import Archiver
from watcher_health import WatcherHealthMonitor

TCP_PORT = 11514
UDP_PORT = 10514
UDP_SERVER = '0.0.0.0'
SERVER = '0.0.0.0'
TCP_ADDR = (SERVER, TCP_PORT)
UDP_ADDR = (UDP_SERVER, UDP_PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

# Controlled by /etc/opensiem/opensiem.conf  [tls] section.
# If the section is absent, TLS is off and the server behaves exactly as before.

_conf = configparser.ConfigParser()
_conf.read('/etc/opensiem/opensiem.conf')

TLS_ENABLED  = _conf.getboolean('tls', 'enabled',  fallback=False)
TLS_CERTFILE = _conf.get('tls', 'certfile', fallback='/etc/opensiem/certs/server.crt')
TLS_KEYFILE  = _conf.get('tls', 'keyfile',  fallback='/etc/opensiem/certs/server.key')

_ssl_ctx = None

if TLS_ENABLED:
    if not os.path.exists(TLS_CERTFILE):
        print(f"[TLS] ERROR: certfile not found: {TLS_CERTFILE}")
        print("[TLS] Generate certs with the script gen_certs.sh")
        sys.exit(1)
    if not os.path.exists(TLS_KEYFILE):
        print(f"[TLS] ERROR: keyfile not found: {TLS_KEYFILE}")
        sys.exit(1)
    _ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    _ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    _ssl_ctx.load_cert_chain(certfile=TLS_CERTFILE, keyfile=TLS_KEYFILE)
    _ssl_ctx.verify_mode = ssl.CERT_NONE

tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp_server.bind(TCP_ADDR)

udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_server.bind(UDP_ADDR)

conn_museum = collector.establish_connection()
LOG_SOURCE_MODULES = {}

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_modules():
    global LOG_SOURCE_MODULES
    modules_dir = os.path.join(os.path.dirname(__file__), 'modules')
    for filename in os.listdir(modules_dir):
        if filename.startswith('parse_') and filename.endswith('.py'):
            module_name = filename[6:-3]
            try:
                module = importlib.import_module(f"modules.{filename[:-3]}")
                LOG_SOURCE_MODULES[module_name] = module
            except Exception as e:
                logging.error(f"Error loading module '{module_name}': {str(e)}")


def signal_handler(sig, frame):
    logging.info('Shutting down server...')
    tcp_server.close()
    conn_museum.close()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def start():
    tcp_server.listen()

    if TLS_ENABLED:
        logging.info(f"[LISTENING] Server is listening on {SERVER}:{TCP_PORT} (TLS enabled, plaintext connections will be rejected)")
    else:
        logging.info(f"[LISTENING] Server is listening on {SERVER}:{TCP_PORT}")

    while True:
        try:
            tcp_conn, tcp_addr = tcp_server.accept()
            tcp_conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            tcp_conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
            tcp_conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
            tcp_conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            tcp_conn.settimeout(None)

            if TLS_ENABLED:
                try:
                    tcp_conn = _ssl_ctx.wrap_socket(tcp_conn, server_side=True)
                except ssl.SSLError as e:
                    logging.warning(
                        f"[TLS] Handshake failed from {tcp_addr}: {e} "
                        f"— connection rejected. Check watcher TLS setting."
                    )
                    tcp_conn.close()
                    continue
                except Exception as e:
                    logging.error(f"[TLS] Unexpected error from {tcp_addr}: {e}")
                    tcp_conn.close()
                    continue

            tcp_thread = threading.Thread(
                target=tcp_handle_client,
                args=(tcp_conn, tcp_addr, LOG_SOURCE_MODULES)
            )
            tcp_thread.start()
            logging.info(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")

        except KeyboardInterrupt:
            logging.info('Ctrl + C detected, shutting down...')
            tcp_server.close()
            conn_museum.close()
            break
        except Exception as e:
            logging.error(f"Error accepting connection: {str(e)}")

    conn_museum.cursor().close()
    conn_museum.close()


import subprocess

if __name__ == "__main__":
    print("Starting the Server, please wait...\n")
    print("Loading Modules")
    load_modules()

    tcp_thread = threading.Thread(target=start)
    tcp_thread.start()

    keyword_updater = KeywordUpdater()
    keyword_updater.start()

    archiver = Archiver()
    archiver.start()

    watcher_health_monitor = WatcherHealthMonitor()
    watcher_health_monitor.start()

    serverstate.start()
    subprocess.Popen(['python3', 'spector_state_observer.py'])
    tcp_thread.join()

