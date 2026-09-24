#!/usr/bin/env python3
import psycopg2
import configparser
from collections import defaultdict
from datetime import datetime
import re
from alarm_system import alarm_system
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import string

config = configparser.ConfigParser()
config.read('/etc/opensiem/opensiem.conf')
db_config = config['database']

log_storage = defaultdict(lambda: defaultdict(lambda: {'count': 0, 'last_seen': None}))

recent_raw = defaultdict(dict)
recent_ids = defaultdict(dict)

use_cases = {}
correlation_rules = defaultdict(list)

def establish_connection():
    return psycopg2.connect(
        host=db_config['host'],
        database=db_config['database'],
        user=db_config['user'],
        password=db_config['password']
    )


def load_data():

    global use_cases, correlation_rules
    print(f"\n{'='*80}")
    correlation_rules.clear()
    use_cases.clear()

    conn = establish_connection()
    cur = conn.cursor()

    cur.execute("SELECT case_id, case_name, entity_field FROM use_cases")
    for row in cur.fetchall():
        case_id, case_name, entity_field = row[0], row[1], (row[2] or 'ip').lower()
        if entity_field not in ('ip', 'user'):
            entity_field = 'ip'
        use_cases[case_id] = {'name': case_name, 'entity_field': entity_field,
                              'severity': 'high'}

    try:
        cur.execute("SELECT case_id, severity FROM use_cases WHERE severity IS NOT NULL")
        for case_id, sev in cur.fetchall():
            if case_id in use_cases and sev:
                use_cases[case_id]['severity'] = sev
    except Exception:
        pass

    cur.execute(
        '''SELECT case_id_fk, msg_id, message, can_repeat, "order"
             FROM special_messages
            ORDER BY case_id_fk, msg_id ASC'''
    )
    rows = cur.fetchall()
    print(f"Found {len(rows)} rows in special_messages")

    for case_id, msg_id, message, can_repeat, order_flag in rows:
        correlation_rules[case_id].append({
            'msg_id': msg_id,
            'message': message,
            'can_repeat': bool(can_repeat),
            'order': bool(order_flag)
        })
        print(f"📌 case_id={case_id}  msg_id={msg_id}  pattern={repr(str(message)[:60])}  "
              f"can_repeat={can_repeat}  order={order_flag}")

    cur.close()
    conn.close()

    total_rules = sum(len(v) for v in correlation_rules.values())
    print(f"Loaded {len(use_cases)} use_cases, {total_rules} rules")
    print(f"{'='*80}\n")


def ensure_loaded():
    if not correlation_rules:
        try:
            load_data()
            print("[AUTO-LOAD] use_cases=", len(use_cases),
                  " rules=", sum(len(v) for v in correlation_rules.values()))
        except Exception as e:
            print("[AUTO-LOAD] load_data failed:", e)

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

def store_for_key(entity_key, message_id, timestamp=None, count=1, raw_line=None, msg_id_fk=None):

    timestamp = timestamp or datetime.now()
    try:
        mid = int(message_id)
    except (ValueError, TypeError):
        print(f"Invalid message ID: {message_id}")
        return

    bucket = log_storage[entity_key]
    if mid in bucket:
        bucket[mid]['count'] += count
    else:
        bucket[mid] = {'count': count, 'last_seen': timestamp}
    bucket[mid]['last_seen'] = timestamp

    if raw_line:
        recent_raw[entity_key][mid] = str(raw_line)
    if msg_id_fk is not None:
        try:
            recent_ids[entity_key][mid] = int(msg_id_fk)
        except Exception:
            recent_ids[entity_key][mid] = None

    print(f"DEBUG: Stored ip={entity_key} msg_id={mid} count={bucket[mid]['count']} last_seen={bucket[mid]['last_seen']}")

def raise_correlation_alarm(case_name, entity_key=None, severity='high', details=None, fk_msg_id=None):

    return alarm_system.raise_alarm(
        case_name=case_name,
        source_ip=entity_key if entity_key else None,
        severity=severity,
        details=details,
        alert_type='correlation',
        fk_msg_id=fk_msg_id
    )

def _artifact_candidate(rule_message) -> str:
    if isinstance(rule_message, dict):
        return _normalize(rule_message.get('raw_message') or '')
    return _normalize(rule_message)


def check_message_match(parsed_log, source_ip_hint=None):

    matches = []

    if isinstance(parsed_log, dict):
        log_text = _to_msg_text(parsed_log)
        src_ip = parsed_log.get('source_ip') or source_ip_hint
    else:
        log_text = _to_msg_text(parsed_log)
        src_ip = source_ip_hint

    if not log_text.strip():
        print("[MATCH] ⚠ Empty log text after extraction → skipping")
        return matches

    log_norm = _normalize(log_text)
    print(f"[MATCH] Raw text : {repr(log_text[:120])}")
    print(f"[MATCH] Normalised: {repr(log_norm[:120])}")
    print(f"[MATCH] Checking against {sum(len(v) for v in correlation_rules.values())} patterns "
          f"across {len(correlation_rules)} cases")

    for case_id, rules in correlation_rules.items():
        uc = use_cases.get(case_id, {'name': f'CASE_{case_id}', 'entity_field': 'ip'})
        case_name = uc['name']

        for rule in rules:
            needle = _artifact_candidate(rule['message'])
            if not needle:
                continue

            hit = needle in log_norm
            if hit:
                entity_key = src_ip or 'unknown-ip'
                print(f"[MATCH] ✔ HIT  needle={repr(needle)}  case={case_name}  "
                      f"msg_id={rule['msg_id']}  ip={entity_key}")
                matches.append({
                    'use_case_id': case_id,
                    'use_case_name': case_name,
                    'entity_field': 'ip',
                    'message_id': rule['msg_id'],
                    'entity_key': entity_key
                })
            else:
                print(f"[MATCH] ✖ MISS needle={repr(needle)}  case={case_name}  msg_id={rule['msg_id']}")

    if not matches:
        print("[MATCH] No matches for this log entry")
    return matches

def _insert_occurrence(alert_id, occurred_at, fk_msg_id, source_ip, raw_line):
    try:
        conn = establish_connection()
        cur = conn.cursor()
        details = json.dumps({"raw_line": raw_line}, ensure_ascii=False)
        cur.execute("""
            INSERT INTO alert_occurrences(alert_id_fk, occurred_at, fk_msg_id, source_ip, details)
            VALUES (%s, %s, %s, %s, %s)
        """, (alert_id, occurred_at, fk_msg_id, source_ip, details))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[occurrence] insert error: {e}")


def _get_last_alert_id_like(case_name, source_ip):

    try:
        conn = establish_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id
              FROM alerts
             WHERE alert_type='correlation'
               AND COALESCE(source_ip::text,'') = COALESCE(%s::text,'')
               AND admin_note LIKE %s
             ORDER BY id DESC
             LIMIT 1
            """,
            (source_ip, f'%\\"case_name\\":\\"{case_name}%')
        )
        row = cur.fetchone()
        cur.close(); conn.close()
        return row[0] if row else None
    except Exception as e:
        print(f"[occurrence] fetch last id error: {e}")
        return None

def evaluate_correlation(entity_key: str = None, time_window_seconds: int = 300):

    now = datetime.now()
    print(f"\n{'='*80}")
    print(f"🔍 EVALUATION START at {now}  source_ip={entity_key or 'ALL'}")
    print(f"🔍 Active storage keys: {list(log_storage.keys())}")

    matched = []

    keys_to_check = [entity_key] if entity_key else list(log_storage.keys())
    for key in keys_to_check:
        if key not in log_storage:
            print(f" Skipping {key} – no data")
            continue

        bucket = log_storage[key]
        print(f" Checking source_ip={key}  msg_ids seen: {list(bucket.keys())}")

        for case_id, rules in correlation_rules.items():
            uc = use_cases.get(case_id, {'name': f'CASE_{case_id}', 'entity_field': 'ip'})
            case_name = uc['name']

            expected_msg_ids = [r['msg_id'] for r in rules]
            print(f" → Case {case_name} expects msg_ids: {expected_msg_ids}")

            found_all = all(mid in bucket and bucket[mid]['count'] >= 1 for mid in expected_msg_ids)
            if not found_all:
                missing = [mid for mid in expected_msg_ids if mid not in bucket or bucket[mid]['count'] < 1]
                print(f"   ✖ Not all found (missing: {missing})")
                continue

            order_required = any(r.get('order') for r in rules)
            order_ok = True
            if order_required:
                seen_ids = set(bucket.keys())
                order_ok = all(mid in seen_ids for mid in expected_msg_ids)
                print(f"   → Order check (lenient): {'OK' if order_ok else 'FAIL'}")

            if found_all and order_ok:
                print(f"\n{'!'*70}")
                print(f"🚨 CORRELATION HIT: {case_name} on ip={key}")

                result = raise_correlation_alarm(
                    f"{case_name} on {key}",
                    entity_key=key,
                    severity=uc.get('severity', 'high'),
                    details={'case_name': case_name, 'entity': key, 'entity_field': uc['entity_field'], 'sequence': expected_msg_ids},
                    fk_msg_id=None
                )
                print('[ALERT-ID result]', result)

                new_id = None
                if isinstance(result, dict) and 'id' in result:
                    new_id = result['id']
                if not new_id:
                    new_id = _get_last_alert_id_like(case_name, key)

                if new_id:
                    print('[WRITE-TRAIL] alert_id=', new_id, 'steps=', expected_msg_ids)
                    for step_mid in expected_msg_ids:
                        ts      = bucket[step_mid]['last_seen']
                        rawline = recent_raw[key].get(step_mid, '')
                        fkid    = recent_ids[key].get(step_mid)
                        _insert_occurrence(new_id, ts, fkid, key, rawline)
                else:
                    print("[occurrence] could not determine alert id; trail not inserted")

                matched.append((key, case_id))

    if matched:
        print(f"\nResetting storage for {len(matched)} matched case(s)")
        for src_ip, case_id in matched:
            for r in correlation_rules[case_id]:
                mid = r['msg_id']
                if src_ip in log_storage and mid in log_storage[src_ip]:
                    log_storage[src_ip][mid]['count'] = 0
                    print(f"  ↺ Reset count for ip={src_ip} msg_id={mid}")
    else:
        print("No correlations triggered → no reset")

    print(f"🔍 EVALUATION END  matched {len(matched)} cases")
    print(f"{'='*80}\n")

def correlate(message_id, message=None, source_ip=None):

    print(f"\n{'─'*60}")
    print(f"[CORRELATE] called  message_id={repr(message_id)}  source_ip={source_ip}")
    print(f"[CORRELATE] message type={type(message).__name__}  value={repr(str(message)[:120])}")

    ensure_loaded()
    print(f"[CORRELATE] rules loaded: {len(correlation_rules)} cases, "
          f"{sum(len(v) for v in correlation_rules.values())} patterns")

    if isinstance(message_id, list):
        message_id = message_id[0] if message_id else None
    print(f"[CORRELATE] message_id after normalise={repr(message_id)}")

    msg_text = _to_msg_text(message)
    print(f"[CORRELATE] msg_text={repr(msg_text[:120])}")
    if not msg_text.strip():
        print("[CORRELATE] ⚠ Empty message text — skipping")
        return

    if isinstance(message, dict):
        log_obj = dict(message)
        if source_ip and not log_obj.get('source_ip'):
            log_obj['source_ip'] = source_ip
    else:
        log_obj = {'message': msg_text}
        if source_ip:
            log_obj['source_ip'] = source_ip

    print(f"[CORRELATE] log_obj keys={list(log_obj.keys())}  "
          f"message excerpt={repr(str(log_obj.get('message',''))[:80])}")

    try:
        matched = check_message_match(log_obj, source_ip_hint=source_ip)
    except Exception as e:
        print(f"[CORRELATE] ⚠ check_message_match raised: {e}")
        matched = []

    print(f"[CORRELATE] check_message_match returned {len(matched)} match(es)")

    maybe_fk_id = None
    if isinstance(message, dict) and 'message_id' in message:
        try:
            maybe_fk_id = int(message['message_id'])
        except Exception:
            maybe_fk_id = None

    entity_key = source_ip or 'unknown-ip'
    print(f"[CORRELATE] entity_key={entity_key}  maybe_fk_id={maybe_fk_id}")

    if matched:
        print(f"[CORRELATE] ✔ Storing {len(matched)} matched step(s)")
        for m in matched:
            ek  = m['entity_key']
            mid = m['message_id']
            print(f"[CORRELATE]   → store_for_key(ek={ek}, mid={mid})")
            store_for_key(ek, mid, raw_line=msg_text, msg_id_fk=maybe_fk_id)

        for m in matched:
            evaluate_correlation(m['entity_key'], time_window_seconds=300)
    else:
        print(f"[CORRELATE] No pattern matched — trying fallback store with message_id={message_id}")
        if message_id is not None:
            print(f"[CORRELATE] ✔ Fallback: store_for_key(ek={entity_key}, mid={message_id})")
            store_for_key(entity_key, message_id, raw_line=msg_text, msg_id_fk=maybe_fk_id)
            evaluate_correlation(entity_key, time_window_seconds=300)
        else:
            print("[CORRELATE] ✖ No pattern match AND no message_id fallback — message dropped")

class _AdminHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/reload':
            try:
                load_data()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'ok': True, 'message': 'Correlation rules reloaded'}).encode())
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
    print("🛠 Admin server listening at http://127.0.0.1:51808 (POST /reload)")

try:
    load_data()
    print("[INIT] use_cases=", len(use_cases),
          " rules=", sum(len(v) for v in correlation_rules.values()))
except Exception as e:
    print("[INIT] load_data failed:", e)

if __name__ == '__main__':
    _start_admin_server()