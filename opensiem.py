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

Connection with multiple watchers, watch if messages get mixed, The correlator needs to watcher for the flow with sender's name (Done)
(The queue or watchout shouldnt be for all messages. just for messages that need to be corelated, its ok if other messages gets mix up, the correlation messages shouldnt, even from their own system. 
If corr_msg 1, corr_msg 2, corr_msg 3, random message from the same system, corr_msg final, the correlation rule need to hit)

Artifacts needs to be pulled (from online datasets) and populated in database periodicly (Done)

A proper method is needed for alams, that will send email if corralation rule is hit, a critical artifact is found and raise alarms if (just notification if anything else is found) (Done)

Raw Log Line goes to NoSQL (Will think about it if needed or not)

---------> Web UI (Done)
If a black listed IP or malicious articate is found, and its ok repeat, Show it as one, dont raise alarm for each hit, just show the count of hits for that artifact or IP address (Done)

Make Deamon 

'''

import banner

import os
import sys
import socket 
import threading
import signal
import importlib
import logging
import subprocess
from collections import defaultdict
from threading import Lock

import collector
import serverstate
from tcphandler import tcp_handle_client
from malicious_keywords_manager import KeywordUpdater


TCP_PORT = 11514
UDP_PORT = 10514

UDP_SERVER = '0.0.0.0'

# SERVER = socket.gethostbyname(socket.gethostname())
# print("=====================================================>", SERVER)

SERVER = '0.0.0.0'

TCP_ADDR = (SERVER, TCP_PORT)
UDP_ADDR = (UDP_SERVER, UDP_PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)    #Reuse the Socket
tcp_server.bind(TCP_ADDR)

udp_server = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)      # For UDP
udp_server.bind(UDP_ADDR)

conn_museum = collector.establish_connection()

LOG_SOURCE_MODULES = {}


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_modules():
    """Dynamically loads parsing modules from the 'modules' directory."""
    global LOG_SOURCE_MODULES

    modules_dir = os.path.join(os.path.dirname(__file__), 'modules')

    for filename in os.listdir(modules_dir):
        if filename.startswith('parse_') and filename.endswith('.py'):
            module_name = filename[6:-3]  # Extract module name (e.g., 'syslog' from 'parse_syslog.py')
            try:
                module = importlib.import_module(f"modules.{filename[:-3]}")  
                LOG_SOURCE_MODULES[module_name] = module
            except Exception as e:
                # print("Error loading module ")
                logging.error(f"Error loading module '{module_name}': {str(e)}")


def signal_handler(sig, frame):
    logging.info('Shutting down server...')
    tcp_server.close()
    conn_museum.close()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def start():

    tcp_server.listen()
    logging.info(f"[LISTENING] Server is listening on {SERVER}:{TCP_PORT}")
    
    while True:
        try:
            tcp_conn, tcp_addr = tcp_server.accept()
            tcp_conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            tcp_conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
            tcp_conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
            tcp_conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)

            tcp_conn.settimeout(None)

            tcp_thread = threading.Thread(target=tcp_handle_client, args=(tcp_conn, tcp_addr,LOG_SOURCE_MODULES))
            tcp_thread.start()

            logging.info(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")

        except KeyboardInterrupt:
            logging.info('Ctrl + C detected, Please wait, Shutting down server...')
            tcp_server.close()
            conn_museum.close()
            break

        except Exception as e:
            logging.error(f"Error accepting connection: {str(e)}")

    conn_museum.cursor().close()
    conn_museum.close()

# def start_spector():
#     subprocess.Popen(['python3', 'spector_state_observer.py'])

import subprocess

if __name__ == "__main__":
    print("Starting the Server, please wait...\n")
    
    print("Loading Modules")
    load_modules()
    
    tcp_thread = threading.Thread(target=start)
    tcp_thread.start()

    keyword_updater = KeywordUpdater()
    keyword_updater.start()

    serverstate.start()
    subprocess.Popen(['python3', 'spector_state_observer.py'])
    tcp_thread.join()
