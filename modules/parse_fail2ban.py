# =============================================================================# ============================================================================= Parser
#
# Handles:
# - Ban / Unban events
# - Authentication failure detections
# - Jail lifecycle (start/stop)
# - Repeat offender / recidivism patterns
# - Backend errors and misconfigurations
#
# Input: Syslog or file-based Fail2Ban logs
# Output: dict compatible with OpenSIEM parser contract
# =============================================================================

import re


_TS_SYSLOG = re.compile(
    r'^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+fail2ban\S*:\s+(?P<body>.+)$'
)

_TS_ISO = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+'
    r'\S+\s+fail2ban\S*:\s+(?P<body>.+)$'
)


BAN = re.compile(r'Ban\s+(?P<ip>\d+\.\d+\.\d+\.\d+)', re.I)
UNBAN = re.compile(r'Unban\s+(?P<ip>\d+\.\d+\.\d+\.\d+)', re.I)

FOUND = re.compile(r'Found\s+(?P<ip>\d+\.\d+\.\d+\.\d+)', re.I)

RETRY = re.compile(
    r'Retry\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\((?P<count>\d+)/(?P<max>\d+)\)',
    re.I
)

JAIL_START = re.compile(r'Jail\s+(?P<jail>\S+)\s+started', re.I)
JAIL_STOP = re.compile(r'Jail\s+(?P<jail>\S+)\s+stopped', re.I)

BACKEND_ERROR = re.compile(
    r'ERROR|Failed to initialize backend|Backend error', re.I
)

JAIL_FIELD = re.compile(r'\[(?P<jail>[^\]]+)\]')


def _extract(rx, text, key):
    m = rx.search(text)
    return m.group(key) if m else ''


def parse_log(log: str) -> dict | None:
    if not log or not log.strip():
        return None

    log = log.strip()
    ts = ''
    hostname = ''
    body = ''

    m = _TS_ISO.match(log)
    if m:
        ts = m.group('timestamp')
        body = m.group('body')
    else:
        m = _TS_SYSLOG.match(log)
        if not m:
            return None
        ts = m.group('timestamp')
        hostname = m.group('host')
        body = m.group('body')

    jail = _extract(JAIL_FIELD, body, 'jail')
    src_ip = ''

    base = {
        'format': 'FAIL2BAN',
        'timestamp': ts,
        'hostname': hostname,
        'process': 'fail2ban',
        'jail': jail,
        'src_ip': '',
        'message': body,
    }

    if m := BAN.search(body):
        src_ip = m.group('ip')
        base.update({
            'format': 'FAIL2BAN_BAN',
            'action': 'BAN',
            'src_ip': src_ip,
            'message': f"Fail2Ban banned IP {src_ip} jail={jail}",
        })
        return base

    if m := UNBAN.search(body):
        src_ip = m.group('ip')
        base.update({
            'format': 'FAIL2BAN_UNBAN',
            'action': 'UNBAN',
            'src_ip': src_ip,
            'message': f"Fail2Ban unbanned IP {src_ip} jail={jail}",
        })
        return base

    if m := RETRY.search(body):
        src_ip = m.group('ip')
        base.update({
            'format': 'FAIL2BAN_RETRY',
            'action': 'RETRY',
            'src_ip': src_ip,
            'attempts': m.group('count'),
            'max_attempts': m.group('max'),
            'message': (
                f"Fail2Ban retry {m.group('count')}/{m.group('max')} "
                f"for IP {src_ip} jail={jail}"
            ),
        })
        return base

    if m := FOUND.search(body):
        src_ip = m.group('ip')
        base.update({
            'format': 'FAIL2BAN_FOUND',
            'action': 'DETECTED',
            'src_ip': src_ip,
            'message': f"Fail2Ban detected failure from IP {src_ip} jail={jail}",
        })
        return base

    if JAIL_START.search(body):
        base.update({
            'format': 'FAIL2BAN_JAIL_START',
            'action': 'JAIL_START',
            'message': f"Fail2Ban jail started jail={jail}",
        })
        return base

    if JAIL_STOP.search(body):
        base.update({
            'format': 'FAIL2BAN_JAIL_STOP',
            'action': 'JAIL_STOP',
            'message': f"Fail2Ban jail stopped jail={jail}",
        })
        return base

    if BACKEND_ERROR.search(body):
        base.update({
            'format': 'FAIL2BAN_BACKEND_ERROR',
            'action': 'ERROR',
            'message': f"Fail2Ban backend error jail={jail}",
        })
        return base

    return base
