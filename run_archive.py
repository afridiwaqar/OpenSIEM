#!/usr/bin/env python3
# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024-present
# See LICENSE for details.
#
# Called by api_archive_run.php and api_archive_rehydrate.php.
# Runs as a subprocess so the PHP request doesn't time out on large archives.
# Prints a single JSON result line to stdout when done.

import sys
import os
import json
import argparse
import logging
import signal
from datetime import date, datetime, timedelta

sys.path.insert(0, './')

os.makedirs('/var/log/opensiem', exist_ok=True)

# Set by the SIGTERM handler when a 'cancel' request comes in via
# rehydrate.php. Checked between partitions/batches so we stop at a clean
# boundary instead of killing the process mid-INSERT and leaving the
# transaction in an aborted state (the same problem that caused the
# earlier login outage).
_cancel_requested = False

def _handle_sigterm(signum, frame):
    global _cancel_requested
    _cancel_requested = True

signal.signal(signal.SIGTERM, _handle_sigterm)

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
            database=d['database'], user=d['user'], password=d['password'],
            # Safety net: if any single statement (or a lock wait) hangs,
            # Postgres kills it after 30s instead of leaving the transaction
            # open indefinitely and starving every other request that
            # touches the same tables. This is what should have auto-healed
            # the job 8 / job 9 deadlock instead of needing a manual kill.
            options='-c statement_timeout=30000'
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
            "UPDATE archive_rehydration SET state = 'running', pid = %s WHERE id = %s",
            (os.getpid(), job_id)
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

        cur.execute(
            "UPDATE archive_rehydration SET partitions_total = %s WHERE id = %s",
            (len(partitions), job_id)
        )
        conn.commit()

        for idx, partition in enumerate(partitions):
            if _cancel_requested:
                logging.info(f"Job {job_id} cancelled after {idx}/{len(partitions)} partitions")
                cur.execute(
                    "UPDATE archive_rehydration "
                    "SET state = 'cancelled', completed_at = now(), "
                    "    rows_imported = %s, partitions_done = %s "
                    "WHERE id = %s",
                    (rows_imported, idx, job_id)
                )
                conn.commit()
                print(json.dumps({'ok': True, 'cancelled': True,
                                  'rows_imported': rows_imported,
                                  'partitions_done': idx}))
                return

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
                # _insert_messages now commits per-partition internally,
                # so a failure on one partition doesn't roll back or hold
                # locks on rows already successfully imported from earlier
                # partitions in this same job.
                rows_imported += _insert_messages(conn, table, job_id)

            # Progress update after every partition — this is what the
            # frontend polls for the progress bar (partitions_done /
            # partitions_total). Cheap relative to the partition work
            # itself, so no need to throttle it.
            cur.execute(
                "UPDATE archive_rehydration "
                "SET partitions_done = %s, rows_imported = %s WHERE id = %s",
                (idx + 1, rows_imported, job_id)
            )
            conn.commit()

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
            database=d['database'], user=d['user'], password=d['password'],
            options='-c statement_timeout=30000'
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

        removed = 0
        if 'messages' in (tables or []):
            # Delete in chunks so every statement stays well inside statement_timeout. The calendar and
            # device rows that belong to those messages go with them: message.date and message.device_id
            # are indexed, so the foreign-key checks are cheap. The matching process and "Log_Source"
            # rows are deliberately LEFT BEHIND (the same as archived data today): message.process_id
            # and message.message_source have no index, so deleting a process / Log_Source row forces a
            # scan of the whole message table, per row, and times out.
            while True:
                cur.execute(
                    """WITH gone AS (
                           DELETE FROM message
                            WHERE message_id IN (SELECT message_id FROM message
                                                  WHERE rehydration_job_id = %s LIMIT 10000)
                        RETURNING date, device_id),
                       c AS (DELETE FROM calendar WHERE data_id   IN (SELECT date      FROM gone)),
                       d AS (DELETE FROM device   WHERE device_id IN (SELECT device_id FROM gone))
                       SELECT count(*) FROM gone""", (job_id,))
                n = cur.fetchone()[0]
                conn.commit()
                removed += n
                if n == 0:
                    break

        cur.execute(
            "UPDATE archive_rehydration "
            "SET state = 'released', released_at = now() WHERE id = %s",
            (job_id,)
        )
        conn.commit()
        conn.close()

        print(json.dumps({'ok': True, 'job_id': job_id, 'state': 'released', 'rows_removed': removed}))

    except Exception as e:
        logging.error(f"Release failed: {e}", exc_info=True)
        print(json.dumps({'ok': False, 'error': str(e)}))


def _insert_messages(conn, table, job_id: int, batch_size: int = 2000) -> int:
    """Re-create archived log lines in the live database.

    Mirrors what collector.museum() writes for a live log line: one new row in
    calendar, "Log_Source", device and process, then the message row that points
    at them. Every message is tagged with rehydration_job_id so that releasing
    the job removes exactly these rows and nothing else.

    (The previous version inserted `FROM calendar WHERE date = <day>` once per
    archived row, i.e. one copy of the message for EVERY calendar row of that day,
    and pointed every message at device/process/source id 1.)
    """
    import json as _json
    from psycopg2.extras import execute_values

    inserted = 0
    for rb in table.to_batches(max_chunksize=batch_size):
        if _cancel_requested:
            break                       # we are between batches: nothing half-written
        b = rb.to_pydict()
        n = rb.num_rows

        def col(name):
            v = b.get(name)
            return v if v is not None else [None] * n

        log_date, log_time = col('log_date'), col('log_time')
        keep = [i for i in range(n) if log_date[i] is not None]   # a row with no date cannot be placed
        if not keep:
            continue
        m = len(keep)
        dev_ip, dev_name = col('device_ip'), col('device_name')
        src_name, src_path = col('source_name'), col('source_path')
        proc, pid = col('process_name'), col('pid')
        text, action, level = col('message'), col('action'), col('level')

        cur = conn.cursor()
        try:
            def ids(seq_sql):
                cur.execute(f"SELECT nextval({seq_sql}) FROM generate_series(1, %s)", (m,))
                return [r[0] for r in cur.fetchall()]

            # Restored rows get NEGATIVE calendar and device ids (dedicated sequences created by
            # rehydration_marker_migration.sql). Live rows are always positive, which is what lets the
            # Logs page tell them apart and keeps its fast id-range search correct for live data.
            cal_ids = ids("'calendar_rehydration_seq'")
            dev_ids = ids("'device_rehydration_seq'")
            src_ids = ids("pg_get_serial_sequence('\"Log_Source\"', 'source_id')")
            prc_ids = ids("pg_get_serial_sequence('process', 'process_id')")

            execute_values(cur, "INSERT INTO calendar (data_id, date, time) VALUES %s",
                [(cal_ids[k], log_date[i], log_time[i] or '00:00:00') for k, i in enumerate(keep)])
            execute_values(cur, 'INSERT INTO "Log_Source" (source_id, source_name, source_path) VALUES %s',
                [(src_ids[k], src_name[i], src_path[i]) for k, i in enumerate(keep)])
            execute_values(cur, "INSERT INTO device (device_id, device_name, device_ip) VALUES %s",
                [(dev_ids[k], dev_name[i] or 'Unknown', dev_ip[i]) for k, i in enumerate(keep)])
            execute_values(cur, "INSERT INTO process (process_id, process_name, pid) VALUES %s",
                [(prc_ids[k], proc[i] or 'Unknown', int(pid[i]) if pid[i] else 0) for k, i in enumerate(keep)])

            msgs = []
            for k, i in enumerate(keep):
                body = {'message': text[i] or ''}
                if action[i]: body['action'] = action[i]
                if level[i]:  body['level'] = level[i]
                msgs.append((src_ids[k], cal_ids[k], _json.dumps(body),
                             src_ids[k], dev_ids[k], prc_ids[k], job_id))
            execute_values(cur,
                "INSERT INTO message (message_source, date, message, log_source, device_id, "
                "process_id, rehydration_job_id) VALUES %s", msgs)
            conn.commit()
            inserted += m
        except Exception as e:
            # A failed statement leaves the transaction aborted: roll back, then STOP. Carrying on
            # would report success with a silently incomplete day, which is not acceptable for logs.
            # Batches already committed carry this job's id, so 'Release' still removes them cleanly.
            logging.error(f"Rehydration batch failed (job {job_id}) after {inserted} rows: {e}")
            conn.rollback()
            raise RuntimeError(f"rehydration stopped after {inserted} rows: {e}") from e
        finally:
            cur.close()
    return inserted


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--date',    help='Target date for archive (YYYY-MM-DD)')
    parser.add_argument('--job',     type=int, help='Rehydration job ID to run')
    parser.add_argument('--release', type=int, help='Rehydration job ID to release')
    args = parser.parse_args()

    if args.date:
        run_archive(args.date)
    elif args.job:
        run_rehydrate(args.job)
    elif args.release:
        run_release(args.release)
    else:
        print(json.dumps({'ok': False, 'error': 'No action specified'}))
        sys.exit(1)
