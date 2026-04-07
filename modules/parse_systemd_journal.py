# =============================================================================
# parse_systemd_journal.py — systemd / journald Log Parser
#
# Handles:
# - Service/unit lifecycle (start, stop, restart, reload)
# - Crash, core-dump, and failure detection
# - Permission / capability errors
# - Authentication & PAM-related messages
# - OOM killer events
# - systemd state transitions
# - journald JSON export and classic text formats
#
# Input:
# - journalctl --output=short
# - journalctl --output=short-iso
# - journalctl --output=json
#
# Output: dict compatible with OpenSIEM parser contract
# =============================================================================

import re
import json


_TS_SHORT = re.compile(
    r'^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<unit>[\w\-.@]+)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<body>.+)$'
)

_TS_ISO = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<unit>[\w\-.@]+)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<body>.+)$'
)


SERVICE_START = re.compile(r'\bStarted\b|\bStarting\b', re.I)
SERVICE_STOP = re.compile(r'\bStopped\b|\bStopping\b', re.I)
SERVICE_RESTART = re.compile(r'\bRestarted\b', re.I)
SERVICE_RELOAD = re.compile(r'\bReloaded\b', re.I)

SERVICE_FAIL = re.compile(
    r'Failed to start|Main process exited|Unit entered failed state|'
    r'crashed|segmentation fault|core dumped',
    re.I
)

PERMISSION_DENY = re.compile(
    r'Permission denied|Operation not permitted|access denied|CAP_[A-Z_]+',
    re.I
)

AUTH_EVENT = re.compile(
    r'Authentication failure|Failed password|Accepted password|'
    r'session opened|session closed|PAM:',
    re.I
)

OOM_EVENT = re.compile(
    r'Out of memory|OOM killer|Killed process',
    re.I
)

STATE_CHANGE = re.compile(
    r'Changed state|Reached target|Dependency failed',
    re.I
)


def _parse_json(log: str) -> dict | None:
    try:
        j = json.loads(log)
    except Exception:
        return None

    return {
        'timestamp': j.get('__REALTIME_TIMESTAMP', ''),
        'hostname': j.get('_HOSTNAME', ''),
        'unit': j.get('_SYSTEMD_UNIT', '') or j.get('SYSLOG_IDENTIFIER', ''),
        'pid': j.get('_PID', ''),
        'body': j.get('MESSAGE', ''),
    }


def parse_log(log: str) -> dict | None:
    if not log or not log.strip():
        return None

    log = log.strip()

    parsed = _parse_json(log)
    if parsed:
        ts = parsed['timestamp']
        hostname = parsed['hostname']
        unit = parsed['unit']
        pid = parsed['pid']
        body = parsed['body']
    else:
        ts = ''
        hostname = ''
        unit = ''
        pid = ''
        body = ''

        m = _TS_ISO.match(log)
        if m:
            ts = m.group('timestamp')
            hostname = m.group('host')
            unit = m.group('unit')
            pid = m.group('pid') or ''
            body = m.group('body')
        else:
            m = _TS_SHORT.match(log)
            if not m:
                return None
            ts = m.group('timestamp')
            hostname = m.group('host')
            unit = m.group('unit')
            pid = m.group('pid') or ''
            body = m.group('body')

    base = {
        'format': 'SYSTEMD',
        'timestamp': ts,
        'hostname': hostname,
        'process': unit,
        'pid': pid,
        'message': body,
    }

    if SERVICE_START.search(body):
        base.update({
            'format': 'SYSTEMD_SERVICE_START',
            'action': 'START',
            'message': f"systemd service started unit={unit}",
        })
        return base

    if SERVICE_STOP.search(body):
        base.update({
            'format': 'SYSTEMD_SERVICE_STOP',
            'action': 'STOP',
            'message': f"systemd service stopped unit={unit}",
        })
        return base

    if SERVICE_RESTART.search(body):
        base.update({
            'format': 'SYSTEMD_SERVICE_RESTART',
            'action': 'RESTART',
            'message': f"systemd service restarted unit={unit}",
        })
        return base

    if SERVICE_RELOAD.search(body):
        base.update({
            'format': 'SYSTEMD_SERVICE_RELOAD',
            'action': 'RELOAD',
            'message': f"systemd service reloaded unit={unit}",
        })
        return base

    if SERVICE_FAIL.search(body):
        base.update({
            'format': 'SYSTEMD_SERVICE_FAILURE',
            'action': 'FAILURE',
            'message': f"systemd service failure unit={unit}",
        })
        return base

    if PERMISSION_DENY.search(body):
        base.update({
            'format': 'SYSTEMD_PERMISSION_DENIED',
            'action': 'ACCESS_DENIED',
            'message': f"systemd permission denied unit={unit}",
        })
        return base

    if AUTH_EVENT.search(body):
        base.update({
            'format': 'SYSTEMD_AUTH_EVENT',
            'action': 'AUTH',
            'message': f"systemd authentication-related activity unit={unit}",
        })
        return base

    if OOM_EVENT.search(body):
        base.update({
            'format': 'SYSTEMD_OOM_KILL',
            'action': 'OOM',
            'message': f"systemd OOM killer event unit={unit}",
        })
        return base

    if STATE_CHANGE.search(body):
        base.update({
            'format': 'SYSTEMD_STATE_CHANGE',
            'action': 'STATE_CHANGE',
            'message': f"systemd state change unit={unit}",
        })
        return base

    return base
