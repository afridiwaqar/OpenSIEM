#!/usr/bin/env python3
# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024-present
# See LICENSE for details.
#
# Correlation Engine v2
# Improvements over v1:
#   1. Time-window enforcement   — steps must occur within configured window
#   2. Entity-field grouping     — group by IP or username per rule
#   3. True sequence ordering    — timestamps must be in correct order
#   4. Rule hit cooldown         — prevent alert storms after a rule fires
#   5. Threshold-based rules     — fire on count >= N within M seconds
#   6. Multi-IP / global bucket  — detect distributed attacks across IPs

import json
import logging
import re
import string
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

import psycopg2
import configparser

from alarm_system import alarm_system

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] correlation: %(message)s'
)
log = logging.getLogger('correlation')

config = configparser.ConfigParser()
config.read('/etc/opensiem/opensiem.conf')
db_config = config['database']

# =============================================================================
# In-memory state
# =============================================================================

# log_storage[entity_key][msg_id] = {
#     'timestamps': [datetime, ...],   # one entry per occurrence
#     'raw_lines':  [str, ...],
#     'fk_ids':     [int|None, ...]
# }
log_storage: dict = defaultdict(lambda: defaultdict(lambda: {
    'timestamps': [],
    'raw_lines':  [],
    'fk_ids':     []
}))

# cooldown_tracker[(entity_key, case_id)] = datetime when rule last fired
cooldown_tracker: dict = {}

# Global bucket for multi-IP / distributed rules (entity_field = 'global')
# Keyed as log_storage but under a single '__global__' entity key
GLOBAL_KEY = '__global__'

use_cases         = {}
correlation_rules = defaultdict(list)

_storage_lock   = threading.Lock()
_cooldown_lock  = threading.Lock()


# =============================================================================
# DB helpers
# =============================================================================

def establish_connection():
    return psycopg2.connect(
        host=db_config['host'],
        database=db_config['database'],
        user=db_config['user'],
        password=db_config['password']
    )


def load_data():
    global use_cases, correlation_rules

    log.info("Loading correlation rules from database")
    print(f"\n{'='*80}")

    with _storage_lock:
        correlation_rules.clear()
        use_cases.clear()

    conn = establish_connection()
    cur  = conn.cursor()

    cur.execute(
        """SELECT case_id, case_name, entity_field, severity,
                  time_window_seconds, cooldown_seconds,
                  threshold_count, threshold_window_seconds
             FROM use_cases"""
    )
    for row in cur.fetchall():
        (case_id, case_name, entity_field, severity,
         time_window, cooldown, threshold_count, threshold_window) = row

        entity_field = (entity_field or 'ip').lower()
        if entity_field not in ('ip', 'user', 'global'):
            entity_field = 'ip'

        use_cases[case_id] = {
            'name':                     case_name,
            'entity_field':             entity_field,
            'severity':                 severity or 'high',
            'time_window_seconds':      int(time_window  or 300),
            'cooldown_seconds':         int(cooldown     or 600),
            'threshold_count':          int(threshold_count)   if threshold_count   else None,
            'threshold_window_seconds': int(threshold_window)  if threshold_window  else None,
        }

    cur.execute(
        '''SELECT case_id_fk, msg_id, message, can_repeat, "order"
             FROM special_messages
            ORDER BY case_id_fk, msg_id ASC'''
    )
    rows = cur.fetchall()
    print(f"Found {len(rows)} rows in special_messages")

    for case_id, msg_id, message, can_repeat, order_flag in rows:
        correlation_rules[case_id].append({
            'msg_id':     msg_id,
            'message':    message,
            'can_repeat': bool(can_repeat),
            'order':      bool(order_flag)
        })

    cur.close()
    conn.close()

    total = sum(len(v) for v in correlation_rules.values())
    print(f"Loaded {len(use_cases)} use_cases, {total} rules")
    print(f"{'='*80}\n")
    log.info(f"Loaded {len(use_cases)} use_cases, {total} patterns")


def ensure_loaded():
    if not correlation_rules:
        try:
            load_data()
        except Exception as e:
            log.error(f"ensure_loaded: load_data failed: {e}")


# =============================================================================
# Text normalisation
# =============================================================================

_ws_re = re.compile(r'\s+')


def _normalize(s: str) -> str:
    if s is None:
        return ''
    s = str(s).strip().lower()
    s = s.strip(string.punctuation + " ")
    s = _ws_re.sub(' ', s)
    return s


def _to_msg_text(message) -> str:
    if message is None:
        return ''
    if isinstance(message, dict):
        for k in ('message', 'raw_message', 'msg', 'text'):
            v = message.get(k)
            if v:
                return str(v)
        try:
            return json.dumps(message, ensure_ascii=False)
        except Exception:
            return str(message)
    return str(message)


def _extract_entity_key(log_obj: dict, entity_field: str, source_ip: str) -> str:
    if entity_field == 'global':
        return GLOBAL_KEY
    if entity_field == 'user':
        user = (log_obj.get('user') or log_obj.get('username') or
                log_obj.get('User') or '').strip()
        if user and user not in ('N/A', '-', ''):
            return f"user:{user}"
    return source_ip or 'unknown-ip'


# =============================================================================
# Storage
# =============================================================================

def store_for_key(entity_key: str, message_id, timestamp=None,
                  raw_line: str = None, msg_id_fk=None):
    timestamp = timestamp or datetime.now()
    try:
        mid = int(message_id)
    except (ValueError, TypeError):
        log.warning(f"Invalid message ID: {message_id}")
        return

    with _storage_lock:
        bucket = log_storage[entity_key][mid]
        bucket['timestamps'].append(timestamp)
        bucket['raw_lines'].append(str(raw_line or ''))
        bucket['fk_ids'].append(msg_id_fk)

    log.debug(f"Stored entity={entity_key} msg_id={mid} "
              f"total_occurrences={len(log_storage[entity_key][mid]['timestamps'])}")


def _prune_old_entries(entity_key: str, window_seconds: int, now: datetime):
    cutoff = now - timedelta(seconds=window_seconds)
    bucket = log_storage.get(entity_key, {})
    for mid, data in list(bucket.items()):
        keep = [(ts, rl, fk)
                for ts, rl, fk in zip(data['timestamps'], data['raw_lines'], data['fk_ids'])
                if ts >= cutoff]
        if keep:
            data['timestamps'], data['raw_lines'], data['fk_ids'] = map(list, zip(*keep))
        else:
            data['timestamps'].clear()
            data['raw_lines'].clear()
            data['fk_ids'].clear()


# =============================================================================
# Pattern matching
# =============================================================================

def check_message_match(log_obj: dict, source_ip: str = None) -> list:
    log_text = _to_msg_text(log_obj)
    if not log_text.strip():
        return []

    log_norm = _normalize(log_text)
    matches  = []

    log.debug(f"Matching: {repr(log_norm[:120])}")

    for case_id, rules in correlation_rules.items():
        uc           = use_cases.get(case_id, {})
        entity_field = uc.get('entity_field', 'ip')
        case_name    = uc.get('name', f'CASE_{case_id}')
        entity_key   = _extract_entity_key(log_obj, entity_field, source_ip)

        for rule in rules:
            needle = _normalize(str(rule['message']))
            if not needle:
                continue
            if needle in log_norm:
                log.debug(f"HIT case={case_name} msg_id={rule['msg_id']} entity={entity_key}")
                matches.append({
                    'use_case_id':   case_id,
                    'use_case_name': case_name,
                    'entity_field':  entity_field,
                    'message_id':    rule['msg_id'],
                    'entity_key':    entity_key
                })

    return matches


# =============================================================================
# Cooldown helpers
# =============================================================================

def _is_on_cooldown(entity_key: str, case_id: int, cooldown_seconds: int) -> bool:
    if cooldown_seconds <= 0:
        return False
    key = (entity_key, case_id)
    with _cooldown_lock:
        last_fired = cooldown_tracker.get(key)
        if last_fired is None:
            return False
        return (datetime.now() - last_fired).total_seconds() < cooldown_seconds


def _set_cooldown(entity_key: str, case_id: int):
    with _cooldown_lock:
        cooldown_tracker[(entity_key, case_id)] = datetime.now()


# =============================================================================
# Alarm
# =============================================================================

def raise_correlation_alarm(case_name, entity_key=None, severity='high',
                            details=None, fk_msg_id=None):
    return alarm_system.raise_alarm(
        case_name=case_name,
        source_ip=entity_key if entity_key and entity_key != GLOBAL_KEY else None,
        severity=severity,
        details=details,
        alert_type='correlation',
        fk_msg_id=fk_msg_id
    )


def _insert_occurrence(alert_id, occurred_at, fk_msg_id, source_ip, raw_line):
    try:
        conn = establish_connection()
        cur  = conn.cursor()
        cur.execute(
            """INSERT INTO alert_occurrences
               (alert_id_fk, occurred_at, fk_msg_id, source_ip, details)
               VALUES (%s, %s, %s, %s, %s)""",
            (alert_id, occurred_at, fk_msg_id, source_ip,
             json.dumps({"raw_line": raw_line}, ensure_ascii=False))
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        log.error(f"occurrence insert error: {e}")


def _get_last_alert_id(case_name: str, source_ip: str):
    try:
        conn = establish_connection()
        cur  = conn.cursor()
        cur.execute(
            """SELECT id FROM alerts
                WHERE alert_type = 'correlation'
                  AND COALESCE(source_ip::text,'') = COALESCE(%s::text,'')
                  AND admin_note LIKE %s
                ORDER BY id DESC LIMIT 1""",
            (source_ip, f'%\\"case_name\\":\\"{case_name}%')
        )
        row = cur.fetchone()
        cur.close()
        conn.close()
        return row[0] if row else None
    except Exception as e:
        log.error(f"fetch last alert id error: {e}")
        return None


# =============================================================================
# Core evaluation
# =============================================================================

def _check_threshold_rule(uc: dict, entity_key: str, now: datetime) -> bool:
    threshold_count  = uc['threshold_count']
    threshold_window = uc['threshold_window_seconds'] or uc['time_window_seconds']
    cutoff = now - timedelta(seconds=threshold_window)

    with _storage_lock:
        bucket = log_storage.get(entity_key, {})
        total_in_window = sum(
            sum(1 for ts in data['timestamps'] if ts >= cutoff)
            for data in bucket.values()
        )

    return total_in_window >= threshold_count


def _check_sequence_rule(rules: list, uc: dict, entity_key: str,
                         now: datetime) -> tuple[bool, list]:
    window_seconds = uc['time_window_seconds']
    order_required = any(r.get('order') for r in rules)
    cutoff         = now - timedelta(seconds=window_seconds)

    with _storage_lock:
        bucket = log_storage.get(entity_key, {})

        # Check every required step has at least one occurrence within the window
        steps_in_window = {}
        for rule in rules:
            mid  = rule['msg_id']
            data = bucket.get(mid)
            if not data:
                return False, []
            recent_ts = [ts for ts in data['timestamps'] if ts >= cutoff]
            if not recent_ts:
                return False, []
            steps_in_window[mid] = recent_ts

    if not order_required:
        return True, list(steps_in_window.keys())

    # True sequence ordering — earliest occurrence of each step must be
    # in ascending order matching the rule's msg_id order
    ordered_mids = [r['msg_id'] for r in rules]
    earliest     = {mid: min(steps_in_window[mid]) for mid in ordered_mids}

    for i in range(len(ordered_mids) - 1):
        if earliest[ordered_mids[i]] > earliest[ordered_mids[i + 1]]:
            log.debug(f"Sequence order violation: step {ordered_mids[i]} "
                      f"at {earliest[ordered_mids[i]]} is after "
                      f"step {ordered_mids[i+1]} at {earliest[ordered_mids[i+1]]}")
            return False, []

    return True, ordered_mids


def _fire_rule(case_id: int, uc: dict, entity_key: str,
               rules: list, matched_mids: list):
    case_name = uc['name']
    severity  = uc.get('severity', 'high')

    log.info(f"CORRELATION HIT: {case_name} entity={entity_key}")

    result = raise_correlation_alarm(
        f"{case_name} on {entity_key}",
        entity_key=entity_key,
        severity=severity,
        details={
            'case_name':    case_name,
            'entity':       entity_key,
            'entity_field': uc['entity_field'],
            'sequence':     matched_mids
        }
    )

    alert_id = None
    if isinstance(result, dict):
        alert_id = result.get('id')
    if not alert_id:
        ip = None if entity_key == GLOBAL_KEY else entity_key
        alert_id = _get_last_alert_id(case_name, ip)

    if alert_id:
        with _storage_lock:
            bucket = log_storage.get(entity_key, {})
            for mid in matched_mids:
                data = bucket.get(mid, {})
                ts_list  = data.get('timestamps', [None])
                rl_list  = data.get('raw_lines',  [''])
                fk_list  = data.get('fk_ids',     [None])
                ts  = ts_list[-1]  if ts_list  else None
                rl  = rl_list[-1]  if rl_list  else ''
                fkid = fk_list[-1] if fk_list  else None
                _insert_occurrence(alert_id, ts, fkid, entity_key, rl)

    _set_cooldown(entity_key, case_id)
    _reset_bucket(entity_key, case_id, rules)


def _reset_bucket(entity_key: str, case_id: int, rules: list):
    with _storage_lock:
        bucket = log_storage.get(entity_key, {})
        for rule in rules:
            mid = rule['msg_id']
            if mid in bucket:
                bucket[mid]['timestamps'].clear()
                bucket[mid]['raw_lines'].clear()
                bucket[mid]['fk_ids'].clear()
    log.debug(f"Reset bucket for entity={entity_key} case_id={case_id}")


def evaluate_correlation(entity_key: str = None, time_window_seconds: int = None):
    now = datetime.now()
    keys_to_check = [entity_key] if entity_key else list(log_storage.keys())

    for key in keys_to_check:
        with _storage_lock:
            has_data = key in log_storage
        if not has_data:
            continue

        for case_id, rules in correlation_rules.items():
            uc = use_cases.get(case_id)
            if not uc:
                continue

            ef = uc['entity_field']

            # Entity field filter — only evaluate this key against rules
            # that match its type
            if ef == 'global' and key != GLOBAL_KEY:
                continue
            if ef != 'global' and key == GLOBAL_KEY:
                continue
            if ef == 'user' and not key.startswith('user:'):
                continue
            if ef == 'ip' and key.startswith('user:'):
                continue

            cooldown_secs = uc.get('cooldown_seconds', 600)
            if _is_on_cooldown(key, case_id, cooldown_secs):
                log.debug(f"Skipping {uc['name']} for {key} — on cooldown")
                continue

            # Prune stale entries before evaluation
            window = uc['time_window_seconds']
            _prune_old_entries(key, window, now)

            # Threshold rule — count-based, no sequence required
            if uc['threshold_count'] is not None:
                if _check_threshold_rule(uc, key, now):
                    log.info(f"Threshold rule hit: {uc['name']} entity={key}")
                    _fire_rule(case_id, uc, key, rules,
                               [r['msg_id'] for r in rules])
                continue

            # Sequence rule — all steps present within window
            hit, matched_mids = _check_sequence_rule(rules, uc, key, now)
            if hit:
                _fire_rule(case_id, uc, key, rules, matched_mids)


# =============================================================================
# Public entry point
# =============================================================================

def correlate(message_id, message=None, source_ip: str = None):
    ensure_loaded()

    msg_text = _to_msg_text(message)
    if not msg_text.strip():
        log.debug("Empty message text — skipping")
        return

    if isinstance(message, dict):
        log_obj = dict(message)
        if source_ip and not log_obj.get('source_ip'):
            log_obj['source_ip'] = source_ip
    else:
        log_obj = {'message': msg_text}
        if source_ip:
            log_obj['source_ip'] = source_ip

    maybe_fk_id = None
    if isinstance(message, dict) and 'message_id' in message:
        try:
            maybe_fk_id = int(message['message_id'])
        except Exception:
            pass

    matched = check_message_match(log_obj, source_ip)

    if matched:
        for m in matched:
            store_for_key(
                m['entity_key'], m['message_id'],
                raw_line=msg_text, msg_id_fk=maybe_fk_id
            )
        evaluated_keys = set()
        for m in matched:
            ek = m['entity_key']
            if ek not in evaluated_keys:
                evaluate_correlation(ek)
                evaluated_keys.add(ek)
    else:
        if message_id is not None:
            entity_key = source_ip or 'unknown-ip'
            store_for_key(entity_key, message_id,
                          raw_line=msg_text, msg_id_fk=maybe_fk_id)
            evaluate_correlation(entity_key)


# =============================================================================
# Reload HTTP server
# =============================================================================

class _AdminHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/reload':
            try:
                load_data()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({
                    'ok': True,
                    'message': 'Correlation rules reloaded',
                    'use_cases': len(use_cases),
                    'patterns': sum(len(v) for v in correlation_rules.values())
                }).encode())
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'ok': False, 'error': str(e)}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        return


def _start_admin_server():
    srv = HTTPServer(('127.0.0.1', 51808), _AdminHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    log.info("Admin server listening at http://127.0.0.1:51808 (POST /reload)")


# =============================================================================
# Init
# =============================================================================

try:
    load_data()
    print("[INIT] use_cases=", len(use_cases),
          " rules=", sum(len(v) for v in correlation_rules.values()))
except Exception as e:
    print("[INIT] load_data failed:", e)

if __name__ == '__main__':
    _start_admin_server()
