# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024–present
# See LICENSE for details.

import socket
import logging
import time

import serverstate
import collector
from messagehandler import processMessage


FORMAT = "utf-8"

logging.basicConfig(level=logging.DEBUG)


def tcp_handle_client(conn, addr, module_dict):
    logging.info(f"[CONNECT] {addr}")

    conn.settimeout(None)

    last_seen = time.time()
    HEARTBEAT_TIMEOUT = 90

    conn_museum = collector.establish_connection()

    buffer = b""

    try:
        while True:
            logging.debug(f"Waiting for data from {addr}")
            data = conn.recv(4096)
            logging.debug(f"Received {len(data)} bytes from {addr}")

            if not data:
                logging.info(f"Client {addr} closed connection")
                break

            buffer += data
            last_seen = time.time()

            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                msg = line.decode(FORMAT, errors="replace").strip()

                if not msg:
                    continue

                if msg == "__HEARTBEAT__":
                    logging.debug(f"[HEARTBEAT] {addr}")
                    continue

                serverstate.record_message(addr, len(msg))
                processMessage(conn, addr, module_dict, msg, conn_museum)

            if time.time() - last_seen > HEARTBEAT_TIMEOUT:
                logging.warning(f"[STALE] Closing inactive client {addr}")
                break

    except Exception:
        logging.exception(f"[ERROR] Client {addr}")

    finally:
        try:
            conn.close()
        except Exception:
            pass
        logging.info(f"[DISCONNECT] {addr}")
