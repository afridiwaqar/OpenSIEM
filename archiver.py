#!/usr/bin/env python3
# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024-present
# See LICENSE for details.

import os
import io
import json
import time
import hashlib
import logging
import threading
import configparser
from datetime import datetime, date, timedelta
from typing import Optional

import psycopg2
import psycopg2.extras

from archive_storage import load_backend_from_db, StorageBackend

log = logging.getLogger(__name__)

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
    PARQUET_AVAILABLE = True
except ImportError:
    PARQUET_AVAILABLE = False
    log.warning("pyarrow not installed — archival disabled. Run: pip install pyarrow")

# Parquet schema

UNIVERSAL_FIELDS = {
    'log_date':     pa.date32(),
    'log_time':     pa.string(),
    'device_ip':    pa.string(),
    'device_name':  pa.string(),
    'source_name':  pa.string(),
    'source_path':  pa.string(),
    'process_name': pa.string(),
    'pid':          pa.int32(),
}

SEMANTIC_FIELDS = {
    'action':     pa.string(),
    'level':      pa.string(),
    'format':     pa.string(),
    'hostname':   pa.string(),
    'user':       pa.string(),
    'client_ip':  pa.string(),
    'message':    pa.string(),
    'raw_message':pa.string(),
}

PARQUET_SCHEMA = pa.schema([
    pa.field('msg_id',       pa.int64()),
    *[pa.field(k, v) for k, v in UNIVERSAL_FIELDS.items()],
    *[pa.field(k, v, nullable=True) for k, v in SEMANTIC_FIELDS.items()],
    pa.field('attributes',   pa.string(), nullable=True),
])

PROMOTED_KEYS = set(SEMANTIC_FIELDS.keys())

def _db_connect() -> psycopg2.extensions.connection:
    cfg = configparser.ConfigParser()
    cfg.read('/etc/opensiem/opensiem.conf')
    d = cfg['database']
    return psycopg2.connect(
        host=d['host'], port=d.get('port', 5432),
        database=d['database'], user=d['user'], password=d['password']
    )


def _load_policy(conn) -> dict:
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT * FROM archive_policy WHERE id = 1")
    row = cur.fetchone()
    cur.close()
    return dict(row) if row else {}


def _audit(conn, action: str, partition_date=None, table_name=None,
           manifest_id=None, detail=None, success=True, error_msg=None,
           performed_by='system'):
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO archive_audit_log
               (action, performed_by, partition_date, table_name,
                manifest_id, detail, success, error_msg)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (action, performed_by, partition_date, table_name,
             manifest_id, json.dumps(detail or {}), success, error_msg)
        )
        conn.commit()
        cur.close()
    except Exception as e:
        log.error(f"Failed to write audit log: {e}")


def _get_or_create_manifest(conn, partition_date: date,
                             table_name: str, backend_type: str,
                             file_path: str, rows_total: int) -> int:
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO archive_manifest
           (partition_date, table_name, file_path, row_count, backend_type,
            rows_total, state)
           VALUES (%s, %s, %s, 0, %s, %s, 'pending')
           ON CONFLICT (partition_date, table_name)
           DO UPDATE SET
               state = CASE WHEN archive_manifest.state = 'deleted_from_hot'
                            THEN archive_manifest.state
                            ELSE 'pending' END,
               rows_total = EXCLUDED.rows_total,
               updated_at = now()
           RETURNING id""",
        (partition_date, table_name, file_path,
         backend_type, rows_total)
    )
    mid = cur.fetchone()[0]
    conn.commit()
    cur.close()
    return mid


def _update_manifest(conn, manifest_id: int, **kwargs):
    if not kwargs:
        return
    sets  = ', '.join(f"{k} = %s" for k in kwargs)
    vals  = list(kwargs.values()) + [manifest_id]
    cur   = conn.cursor()
    cur.execute(
        f"UPDATE archive_manifest SET {sets}, updated_at = now() WHERE id = %s",
        vals
    )
    conn.commit()
    cur.close()

def _update_schema_registry(conn, keys_seen: dict):
    if not keys_seen:
        return
    cur = conn.cursor()
    for key, (count, example) in keys_seen.items():
        cur.execute(
            """INSERT INTO archive_schema_registry
               (key, occurrence_count, example_value)
               VALUES (%s, %s, %s)
               ON CONFLICT (key) DO UPDATE SET
                   last_seen        = now(),
                   occurrence_count = archive_schema_registry.occurrence_count + EXCLUDED.occurrence_count,
                   example_value    = COALESCE(EXCLUDED.example_value, archive_schema_registry.example_value)
            """,
            (key, count, str(example)[:200] if example else None)
        )
    conn.commit()
    cur.close()

def _row_to_parquet_record(row: dict) -> dict:
    msg = row.get('message_json') or {}
    if isinstance(msg, str):
        try:
            msg = json.loads(msg)
        except Exception:
            msg = {}

    attributes = {}
    for k, v in msg.items():
        if k in PROMOTED_KEYS:
            continue
        attributes[k] = v

    record = {
        'msg_id':       row.get('msg_id'),
        'log_date':     row.get('log_date'),
        'log_time':     str(row.get('log_time', '')),
        'device_ip':    row.get('device_ip', ''),
        'device_name':  row.get('device_name', ''),
        'source_name':  row.get('source_name', ''),
        'source_path':  row.get('source_path', ''),
        'process_name': row.get('process_name', ''),
        'pid':          row.get('pid'),
        'action':       msg.get('action'),
        'level':        msg.get('level'),
        'format':       msg.get('format'),
        'hostname':     msg.get('hostname'),
        'user':         msg.get('user'),
        'client_ip':    msg.get('client_ip'),
        'message':      msg.get('message'),
        'raw_message':  msg.get('raw_message'),
        'attributes':   json.dumps(attributes) if attributes else None,
    }
    return record


def _fetch_messages_for_date(conn, target_date: date, batch_size=5000):
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor,
                      name='archive_cursor')
    cur.itersize = batch_size
    cur.execute(
        """
        SELECT
            m.message_source AS msg_id,
            c.Date           AS log_date,
            c.time           AS log_time,
            d.device_ip,
            d.device_name,
            ls.source_name,
            ls.source_path,
            p.process_name,
            p.pid::int       AS pid,
            m.message        AS message_json
        FROM Message m
        JOIN Calendar   c  ON c.data_id   = m.Date
        JOIN Device     d  ON d.device_id = m.device_id
        JOIN "Log_Source" ls ON ls.source_id = m.log_source
        JOIN Process    p  ON p.process_id = m.process_id
        WHERE c.Date = %s
        ORDER BY m.message_source
        """,
        (target_date,)
    )
    return cur


def _build_parquet_bytes(rows: list, compression: str = 'zstd') -> bytes:
    if not rows:
        return b'', {}

    columns = {field.name: [] for field in PARQUET_SCHEMA}
    keys_seen = {}

    for row in rows:
        record = _row_to_parquet_record(row)
        for field in PARQUET_SCHEMA:
            val = record.get(field.name)
            columns[field.name].append(val)

        msg = row.get('message_json') or {}
        if isinstance(msg, str):
            try:
                msg = json.loads(msg)
            except Exception:
                msg = {}
        for k, v in msg.items():
            if k not in PROMOTED_KEYS:
                if k not in keys_seen:
                    keys_seen[k] = [0, v]
                keys_seen[k][0] += 1

    arrays = []
    for field in PARQUET_SCHEMA:
        raw = columns[field.name]
        if pa.types.is_int64(field.type) or pa.types.is_int32(field.type):
            arr = pa.array(
                [int(v) if v is not None else None for v in raw],
                type=field.type
            )
        elif pa.types.is_date32(field.type):
            arr = pa.array(raw, type=pa.date32())
        else:
            arr = pa.array(
                [str(v) if v is not None else None for v in raw],
                type=pa.string()
            )
        arrays.append(arr)

    table = pa.Table.from_arrays(arrays, schema=PARQUET_SCHEMA)

    buf = io.BytesIO()
    pq.write_table(
        table, buf,
        compression=compression if compression != 'none' else None,
        write_statistics=True,
        row_group_size=50000,
    )
    return buf.getvalue(), keys_seen

def archive_date(target_date: date, policy: dict,
                 backend: StorageBackend, conn) -> dict:
    result = {
        'date':        str(target_date),
        'tables':      {},
        'ok':          False,
        'rows_total':  0,
        'bytes_total': 0,
    }

    tables_to_archive = []
    if policy.get('archive_messages', True):
        tables_to_archive.append('messages')
    if policy.get('archive_alerts', True):
        tables_to_archive.append('alerts')

    compression    = policy.get('compression', 'zstd')
    encrypt        = policy.get('encrypt_at_rest', False)
    partial_behav  = policy.get('partial_export_behaviour', 'keep')
    verify_after   = policy.get('verify_after_export', True)
    delete_after   = policy.get('delete_after_verify', True)

    all_ok = True

    for table_name in tables_to_archive:
        log.info(f"[ARCHIVE] Starting {table_name} for {target_date}")

        year  = target_date.year
        month = f"{target_date.month:02d}"
        day   = f"{target_date.day:02d}"
        file_path = (f"opensiem_{table_name}/"
                     f"year={year}/month={month}/day={day}/"
                     f"{table_name}_{target_date}.parquet")

        cur = conn.cursor()
        cur.execute(
            """SELECT COUNT(*) FROM Message m
               JOIN Calendar c ON c.data_id = m.Date
               WHERE c.Date = %s""",
            (target_date,)
        ) if table_name == 'messages' else cur.execute(
            "SELECT 0"
        )
        rows_total = cur.fetchone()[0]
        cur.close()

        if rows_total == 0:
            log.info(f"[ARCHIVE] No rows for {table_name} on {target_date} — skipping")
            continue

        mid = _get_or_create_manifest(
            conn, target_date, table_name, 'active_backend', file_path, rows_total
        )

        cur = conn.cursor()
        cur.execute(
            "SELECT state, frozen FROM archive_manifest WHERE id = %s", (mid,)
        )
        row = cur.fetchone()
        cur.close()

        if row and row[1]:
            log.info(f"[ARCHIVE] {table_name} {target_date} is FROZEN — skipping")
            continue

        if row and row[0] == 'deleted_from_hot':
            log.info(f"[ARCHIVE] {table_name} {target_date} already archived — skipping")
            continue

        _update_manifest(conn, mid, state='exporting')
        _audit(conn, 'archive_started', target_date, table_name, mid,
               {'rows_total': rows_total})

        try:
            fetch_cur  = _fetch_messages_for_date(conn, target_date)
            batch_rows = []
            all_keys   = {}
            rows_exported = 0

            for db_row in fetch_cur:
                batch_rows.append(dict(db_row))
                if len(batch_rows) >= 5000:
                    data, keys = _build_parquet_bytes(batch_rows, compression)
                    for k, (cnt, ex) in keys.items():
                        if k not in all_keys:
                            all_keys[k] = [0, ex]
                        all_keys[k][0] += cnt
                    rows_exported += len(batch_rows)
                    batch_rows = []

            if batch_rows:
                data, keys = _build_parquet_bytes(batch_rows, compression)
                for k, (cnt, ex) in keys.items():
                    if k not in all_keys:
                        all_keys[k] = [0, ex]
                    all_keys[k][0] += cnt
                rows_exported += len(batch_rows)

            fetch_cur.close()

            full_data, _ = _build_parquet_bytes([], compression)

            cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            cur.execute(
                """
                SELECT
                    m.message_source AS msg_id,
                    c.Date AS log_date, c.time AS log_time,
                    d.device_ip, d.device_name,
                    ls.source_name, ls.source_path,
                    p.process_name, p.pid::int AS pid,
                    m.message AS message_json
                FROM Message m
                JOIN Calendar   c  ON c.data_id   = m.Date
                JOIN Device     d  ON d.device_id = m.device_id
                JOIN "Log_Source" ls ON ls.source_id = m.log_source
                JOIN Process    p  ON p.process_id = m.process_id
                WHERE c.Date = %s
                ORDER BY m.message_source
                """,
                (target_date,)
            )
            all_rows = [dict(r) for r in cur.fetchall()]
            cur.close()

            full_data, keys = _build_parquet_bytes(all_rows, compression)
            all_keys = keys
            rows_exported = len(all_rows)

            if encrypt:
                full_data = _encrypt_bytes(full_data)

            sha256 = hashlib.sha256(full_data).hexdigest()

            ok = backend.write(file_path, full_data)
            if not ok:
                raise RuntimeError("Backend write returned False")

            _update_schema_registry(conn, all_keys)

            _update_manifest(conn, mid,
                state='exported',
                row_count=rows_exported,
                rows_exported=rows_exported,
                file_size_bytes=len(full_data),
                sha256_hash=sha256,
                encrypted=encrypt,
                partial=(rows_exported < rows_total),
            )

            if verify_after:
                log.info(f"[ARCHIVE] Verifying {table_name} {target_date}")
                verified = _verify_partition(backend, file_path, sha256, mid)
                if not verified:
                    _update_manifest(conn, mid, state='verify_failed')
                    _audit(conn, 'integrity_failed', target_date, table_name, mid,
                           success=False, error_msg='Hash mismatch after write')
                    all_ok = False
                    continue
                _update_manifest(conn, mid,
                    state='verified', verified_at=datetime.utcnow())
                _audit(conn, 'integrity_verified', target_date, table_name, mid)

            if delete_after and (rows_exported == rows_total or
                                  partial_behav == 'delete_exported'):
                _delete_from_hot(conn, target_date, table_name, mid, rows_exported)

            result['tables'][table_name] = {
                'rows': rows_exported,
                'bytes': len(full_data),
                'sha256': sha256,
            }
            result['rows_total']  += rows_exported
            result['bytes_total'] += len(full_data)

            _audit(conn, 'archive_completed', target_date, table_name, mid,
                   {'rows': rows_exported, 'bytes': len(full_data)})
            log.info(f"[ARCHIVE] Completed {table_name} {target_date}: "
                     f"{rows_exported} rows, {len(full_data)//1024} KB")

        except Exception as e:
            conn.rollback()
            log.error(f"[ARCHIVE] Failed {table_name} {target_date}: {e}", exc_info=True)
            _update_manifest(conn, mid, state='failed', error_msg=str(e))
            _audit(conn, 'archive_failed', target_date, table_name, mid,
                   success=False, error_msg=str(e))
            all_ok = False

    result['ok'] = all_ok
    return result


def _verify_partition(backend: StorageBackend, file_path: str,
                      expected_sha256: str, manifest_id: int) -> bool:
    try:
        data = backend.read(file_path)
        if data is None:
            return False
        actual = hashlib.sha256(data).hexdigest()
        return actual == expected_sha256
    except Exception as e:
        log.error(f"[ARCHIVE] Verification read failed: {e}")
        return False


def _delete_from_hot(conn, target_date: date, table_name: str,
                     manifest_id: int, rows_deleted: int):
    try:
        cur = conn.cursor()
        if table_name == 'messages':
            cur.execute(
                """DELETE FROM Message
                   WHERE Date IN (
                       SELECT data_id FROM Calendar WHERE Date = %s
                   )""",
                (target_date,)
            )
        elif table_name == 'alerts':
            cur.execute(
                "DELETE FROM alerts WHERE created_at::date = %s",
                (target_date,)
            )
        conn.commit()
        cur.close()
        _update_manifest(conn, manifest_id,
            state='deleted_from_hot',
            deleted_at=datetime.utcnow())
        _audit(conn, 'deleted_from_hot', target_date, table_name, manifest_id,
               {'rows_deleted': rows_deleted})
        log.info(f"[ARCHIVE] Deleted {rows_deleted} rows from hot storage: "
                 f"{table_name} {target_date}")
    except Exception as e:
        log.error(f"[ARCHIVE] Failed to delete from hot: {e}")
        conn.rollback()


def _encrypt_bytes(data: bytes) -> bytes:
    key_path = '/etc/opensiem/certs/archive.key'
    try:
        from cryptography.fernet import Fernet
        with open(key_path, 'rb') as f:
            key = f.read().strip()
        return Fernet(key).encrypt(data)
    except ImportError:
        log.warning("cryptography not installed — skipping encryption")
        return data


# Archive thread — runs inside opensiem.py

class Archiver(threading.Thread):

    def __init__(self):
        super().__init__(daemon=True, name='ArchiverThread')
        self._stop_event = threading.Event()

    def run(self):
        if not PARQUET_AVAILABLE:
            log.warning("[ARCHIVE] pyarrow not available — archiver thread exiting")
            return

        log.info("[ARCHIVE] Archiver thread started")

        while not self._stop_event.is_set():
            try:
                self._tick()
            except Exception as e:
                log.error(f"[ARCHIVE] Unexpected error in tick: {e}", exc_info=True)
            self._stop_event.wait(60)

    def _tick(self):
        conn = _db_connect()
        try:
            policy = _load_policy(conn)
            if not policy.get('enabled', False):
                conn.close()
                return

            run_time_str = str(policy.get('run_time', '02:00:00'))[:5]
            now_str      = datetime.now().strftime('%H:%M')

            if now_str != run_time_str:
                conn.close()
                return

            log.info("[ARCHIVE] Scheduled run starting")
            backend = load_backend_from_db(conn)
            if not backend:
                log.error("[ARCHIVE] No active storage backend configured")
                conn.close()
                return

            hot_days      = policy.get('hot_retention_days', 90)
            cutoff        = date.today() - timedelta(days=hot_days)
            target        = cutoff - timedelta(days=1)

            result = archive_date(target, policy, backend, conn)
            log.info(f"[ARCHIVE] Run complete: {result}")

            self._enforce_cold_retention(conn, policy)

        finally:
            conn.close()

        self._stop_event.wait(61)

    def _enforce_cold_retention(self, conn, policy: dict):
        cold_days = policy.get('cold_retention_days', 1095)
        if not cold_days:
            return
        cutoff = date.today() - timedelta(days=cold_days)
        cur = conn.cursor()
        cur.execute(
            """SELECT id, partition_date, table_name, file_path
               FROM archive_manifest
               WHERE partition_date < %s
                 AND state = 'deleted_from_hot'
                 AND frozen = false""",
            (cutoff,)
        )
        rows = cur.fetchall()
        cur.close()

        if not rows:
            return

        backend = load_backend_from_db(conn)
        if not backend:
            return

        for mid, pdate, tname, fpath in rows:
            try:
                backend.delete(fpath)
                cur = conn.cursor()
                cur.execute("DELETE FROM archive_manifest WHERE id = %s", (mid,))
                conn.commit()
                cur.close()
                _audit(conn, 'cold_partition_deleted', pdate, tname, mid,
                       {'reason': f'cold_retention={cold_days} days'})
                log.info(f"[ARCHIVE] Cold retention: deleted {tname} {pdate}")
            except Exception as e:
                log.error(f"[ARCHIVE] Failed to delete cold partition {mid}: {e}")

    def stop(self):
        self._stop_event.set()


def run_manual_archive(target_date: date) -> dict:
    if not PARQUET_AVAILABLE:
        return {'ok': False, 'error': 'pyarrow not installed'}
    conn = _db_connect()
    try:
        policy  = _load_policy(conn)
        backend = load_backend_from_db(conn)
        if not backend:
            return {'ok': False, 'error': 'No active storage backend'}
        return archive_date(target_date, policy, backend, conn)
    finally:
        conn.close()
