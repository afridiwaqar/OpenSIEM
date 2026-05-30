#!/usr/bin/env python3
# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024-present
# See LICENSE for details.
#
# Called by api_archive_run.php and api_archive_rehydrate.php.
# Runs as a subprocess so the PHP request doesn't time out on large archives.
# Prints a single JSON result line to stdout when done.

import sys
import json
import argparse
import logging
from datetime import date, datetime, timedelta

sys.path.insert(0, './')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler('/var/log/opensiem/archiver.log'),
              logging.StreamHandler(sys.stderr)]
)


def run_archive(target_date_str: str):
    from archiver import run_manual_archive
    try:
        target = date.fromisoformat(target_date_str)
        result = run_manual_archive(target)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({'ok': False, 'error': str(e)}))


def run_rehydrate(job_id: int):
    try:
        import psycopg2, configparser, psycopg2.extras
        from archive_storage import load_backend_from_db

        cfg = configparser.ConfigParser()
        cfg.read('/etc/opensiem/opensiem.conf')
        d = cfg['database']
        conn = psycopg2.connect(
            host=d['host'], port=d.get('port', 5432),
            database=d['database'], user=d['user'], password=d['password']
        )
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("SELECT * FROM archive_rehydration WHERE id = %s", (job_id,))
        job = cur.fetchone()

        if not job:
            print(json.dumps({'ok': False, 'error': f'Job {job_id} not found'}))
            return

        date_from  = job['date_from']
        date_to    = job['date_to']
        tables     = job['tables']

        cur.execute(
            "UPDATE archive_rehydration SET state = 'running' WHERE id = %s",
            (job_id,)
        )
        conn.commit()

        cur.execute(
            "SELECT file_path, table_name, sha256_hash, encrypted "
            "FROM archive_manifest "
            "WHERE partition_date BETWEEN %s AND %s "
            "  AND table_name = ANY(%s) "
            "  AND state IN ('verified', 'deleted_from_hot') "
            "ORDER BY partition_date, table_name",
            (date_from, date_to, tables)
        )
        partitions = cur.fetchall()

        if not partitions:
            cur.execute(
                "UPDATE archive_rehydration SET state = 'active', "
                "completed_at = now(), rows_imported = 0 WHERE id = %s",
                (job_id,)
            )
            conn.commit()
            print(json.dumps({'ok': True, 'rows_imported': 0,
                              'warning': 'No partitions found in range'}))
            return

        backend    = load_backend_from_db(conn)
        if not backend:
            print(json.dumps({'ok': False, 'error': 'No active storage backend configured'}))
            return

        try:
            import pyarrow.parquet as pq
            import pyarrow as pa
        except ImportError:
            print(json.dumps({'ok': False, 'error': 'pyarrow not installed'}))
            return

        rows_imported = 0

        for partition in partitions:
            file_path  = partition['file_path']
            table_name = partition['table_name']

            file_data = backend.read(file_path)
            if file_data is None:
                logging.warning(f"Could not read partition: {file_path}")
                continue

            import hashlib
            if partition['sha256_hash']:
                actual = hashlib.sha256(file_data).hexdigest()
                if actual != partition['sha256_hash']:
                    logging.error(f"Hash mismatch on rehydration: {file_path}")
                    continue

            if partition['encrypted']:
                from archive_storage import _decrypt_credentials
                key_path = '/etc/opensiem/certs/archive.key'
                try:
                    from cryptography.fernet import Fernet
                    with open(key_path, 'rb') as f:
                        key = f.read().strip()
                    file_data = Fernet(key).decrypt(file_data)
                except Exception as e:
                    logging.error(f"Decryption failed for {file_path}: {e}")
                    continue

            import io
            table = pq.read_table(io.BytesIO(file_data))

            if table_name == 'messages':
                rows_imported += _insert_messages(conn, table)

        cur.execute(
            "UPDATE archive_rehydration "
            "SET state = 'active', completed_at = now(), rows_imported = %s "
            "WHERE id = %s",
            (rows_imported, job_id)
        )
        conn.commit()
        conn.close()

        print(json.dumps({'ok': True, 'rows_imported': rows_imported,
                          'job_id': job_id}))

    except Exception as e:
        logging.error(f"Rehydration failed: {e}", exc_info=True)
        print(json.dumps({'ok': False, 'error': str(e)}))


def run_release(job_id: int):
    try:
        import psycopg2, configparser

        cfg = configparser.ConfigParser()
        cfg.read('/etc/opensiem/opensiem.conf')
        d = cfg['database']
        conn = psycopg2.connect(
            host=d['host'], port=d.get('port', 5432),
            database=d['database'], user=d['user'], password=d['password']
        )
        cur = conn.cursor()
        cur.execute(
            "SELECT date_from, date_to, tables FROM archive_rehydration WHERE id = %s",
            (job_id,)
        )
        job = cur.fetchone()
        if not job:
            print(json.dumps({'ok': False, 'error': 'Job not found'}))
            return

        date_from, date_to, tables = job

        if 'messages' in (tables or []):
            cur.execute(
                """DELETE FROM message
                   WHERE date IN (
                       SELECT data_id FROM calendar
                       WHERE date BETWEEN %s AND %s
                   )
                   AND message_source IN (
                       SELECT msg_id FROM archive_manifest
                       WHERE partition_date BETWEEN %s AND %s
                         AND state = 'deleted_from_hot'
                   )""",
                (date_from, date_to, date_from, date_to)
            )

        cur.execute(
            "UPDATE archive_rehydration "
            "SET state = 'released', released_at = now() WHERE id = %s",
            (job_id,)
        )
        conn.commit()
        conn.close()

        print(json.dumps({'ok': True, 'job_id': job_id, 'state': 'released'}))

    except Exception as e:
        logging.error(f"Release failed: {e}", exc_info=True)
        print(json.dumps({'ok': False, 'error': str(e)}))


def _insert_messages(conn, table) -> int:
    import json as _json
    cur  = conn.cursor()
    rows = table.to_pydict()
    n    = len(rows.get('msg_id', []))
    if n == 0:
        return 0

    inserted = 0
    for i in range(n):
        try:
            log_date = rows['log_date'][i]
            msg_id   = rows['msg_id'][i]

            msg_json = _json.dumps({
                'message':     rows.get('message',     [None])[i] or '',
                'action':      rows.get('action',      [None])[i] or '',
                'level':       rows.get('level',       [None])[i] or '',
                'raw_message': rows.get('raw_message', [None])[i] or '',
            })

            cur.execute(
                """INSERT INTO message
                   (message_source, date, message, log_source, device_id, process_id)
                   SELECT %s, data_id, %s, 1, 1, 1
                   FROM calendar WHERE date = %s
                   ON CONFLICT DO NOTHING""",
                (msg_id, msg_json, log_date)
            )
            inserted += cur.rowcount
        except Exception as e:
            logging.warning(f"Row insert failed (row {i}): {e}")
            conn.rollback()
            continue

    conn.commit()
    cur.close()
    return inserted


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--date',    help='Target date for archive (YYYY-MM-DD)')
    parser.add_argument('--job',     type=int, help='Rehydration job ID to run')
    parser.add_argument('--release', type=int, help='Rehydration job ID to release')
    args = parser.parse_args()

    os.makedirs('/var/log/opensiem', exist_ok=True)

    import os
    if args.date:
        run_archive(args.date)
    elif args.job:
        run_rehydrate(args.job)
    elif args.release:
        run_release(args.release)
    else:
        print(json.dumps({'ok': False, 'error': 'No action specified'}))
        sys.exit(1)
