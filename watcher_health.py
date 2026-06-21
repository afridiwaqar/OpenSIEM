#!/usr/bin/env python3
# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024-present
# See LICENSE for details.

import time
import threading
import logging
import configparser
from datetime import datetime, timedelta

import psycopg2
import psycopg2.extras

from alarm_system import alarm_system

log = logging.getLogger("watcher_health")


def _db_connect():
    cfg = configparser.ConfigParser()
    cfg.read('/etc/opensiem/opensiem.conf')
    d = cfg['database']
    return psycopg2.connect(
        host=d['host'], database=d['database'],
        user=d['user'], password=d['password']
    )


def record_heartbeat(source_ip: str, client_name: str = None):
    """
    Call this every time a heartbeat or any message is received from a watcher.
    Updates last_heartbeat_at and clears offline status if the watcher had
    been marked offline (triggers recovery notification).
    """
    conn = _db_connect()
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO watcher_health (client_name, source_ip, last_heartbeat_at, last_message_at)
               VALUES (%s, %s, now(), now())
               ON CONFLICT (source_ip) DO UPDATE SET
                   last_heartbeat_at = now(),
                   last_message_at   = now(),
                   client_name       = COALESCE(EXCLUDED.client_name, watcher_health.client_name),
                   updated_at        = now()
               RETURNING is_online, marked_offline_at, alert_id_fk""",
            (client_name, source_ip)
        )
        was_offline, marked_offline_at, alert_id = cur.fetchone()
        conn.commit()

        if was_offline is False:
            _mark_online(conn, source_ip, client_name, alert_id)

        cur.close()
    except Exception as e:
        log.error(f"record_heartbeat failed for {source_ip}: {e}")
        conn.rollback()
    finally:
        conn.close()


def _mark_online(conn, source_ip: str, client_name: str, prior_alert_id):
    cur = conn.cursor()
    cur.execute(
        """UPDATE watcher_health
           SET is_online = true, marked_offline_at = NULL, alert_id_fk = NULL
           WHERE source_ip = %s""",
        (source_ip,)
    )
    conn.commit()
    cur.close()

    name = client_name or source_ip
    log.info(f"[WATCHER HEALTH] {name} ({source_ip}) is back online")

    try:
        alarm_system.raise_alarm(
            case_name=f"Watcher recovered: {name}",
            source_ip=source_ip,
            severity='low',
            details={
                "client_name": name,
                "source_ip": source_ip,
                "message": f"Watcher {name} resumed sending heartbeats after being offline."
            },
            alert_type='watcher_health'
        )
    except Exception as e:
        log.warning(f"Failed to raise recovery notification for {source_ip}: {e}")


def _get_settings(conn) -> dict:
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT * FROM watcher_health_settings WHERE id = 1")
    row = cur.fetchone()
    cur.close()
    return dict(row) if row else {
        'enabled': True,
        'default_offline_threshold_minutes': 5,
        'check_interval_seconds': 60,
    }


def _check_offline_watchers(conn, settings: dict):
    default_minutes = settings.get('default_offline_threshold_minutes', 5)

    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute(
        """SELECT id, client_name, source_ip, last_heartbeat_at,
                  offline_threshold_minutes, is_online
           FROM watcher_health
           WHERE is_online = true"""
    )
    rows = cur.fetchall()
    cur.close()

    now = datetime.now(rows[0]['last_heartbeat_at'].tzinfo) if rows else None

    for row in rows:
        threshold = row['offline_threshold_minutes'] or default_minutes
        elapsed = now - row['last_heartbeat_at']

        if elapsed > timedelta(minutes=threshold):
            _mark_offline(conn, row, threshold, elapsed)


def _mark_offline(conn, row, threshold_minutes: int, elapsed: timedelta):
    source_ip   = row['source_ip']
    client_name = row['client_name'] or source_ip
    minutes_silent = int(elapsed.total_seconds() // 60)

    cur = conn.cursor()
    cur.execute(
        """UPDATE watcher_health
           SET is_online = false, marked_offline_at = now()
           WHERE id = %s""",
        (row['id'],)
    )
    conn.commit()
    cur.close()

    log.warning(
        f"[WATCHER HEALTH] {client_name} ({source_ip}) offline — "
        f"no heartbeat for {minutes_silent} min (threshold {threshold_minutes} min)"
    )

    try:
        result = alarm_system.raise_alarm(
            case_name=f"Watcher offline: {client_name}",
            source_ip=source_ip,
            severity='high',
            details={
                "client_name": client_name,
                "source_ip": source_ip,
                "minutes_silent": minutes_silent,
                "threshold_minutes": threshold_minutes,
                "message": (
                    f"Watcher {client_name} has not sent a heartbeat in "
                    f"{minutes_silent} minutes (threshold: {threshold_minutes} minutes)."
                )
            },
            alert_type='watcher_health'
        )
        alert_id = result.get('id')
        if alert_id:
            cur = conn.cursor()
            cur.execute(
                "UPDATE watcher_health SET alert_id_fk = %s WHERE id = %s",
                (alert_id, row['id'])
            )
            conn.commit()
            cur.close()
    except Exception as e:
        log.error(f"Failed to raise offline alarm for {source_ip}: {e}")


class WatcherHealthMonitor(threading.Thread):

    def __init__(self):
        super().__init__(daemon=True, name='WatcherHealthMonitor')
        self._stop_event = threading.Event()

    def run(self):
        log.info("Watcher health monitor started")
        while not self._stop_event.is_set():
            try:
                conn = _db_connect()
                try:
                    settings = _get_settings(conn)
                    if settings.get('enabled', True):
                        _check_offline_watchers(conn, settings)
                    interval = settings.get('check_interval_seconds', 60)
                finally:
                    conn.close()
            except Exception as e:
                log.error(f"Watcher health check failed: {e}", exc_info=True)
                interval = 60

            self._stop_event.wait(interval)

    def stop(self):
        self._stop_event.set()
