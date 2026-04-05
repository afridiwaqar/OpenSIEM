import re

# =============================================================================
# parse_postgresql.py — PostgreSQL Log Parser
#
# Source: /var/log/postgresql/postgresql-*.log
#         (or wherever pg_log is configured)
#
# Formats handled:
#   1. Standard PostgreSQL log format (log_line_prefix = '%t [%p]: [%l-1] ')
#   2. csvlog format (partial — key fields only)
#   3. Modern format with session/duration info
# =============================================================================

# ── 1. Standard format ────────────────────────────────────────────────────────
# 2026-03-07 01:25:47.123 +0500 [12345] user@database LOG:  duration: 5.123 ms  statement: SELECT ...
# 2026-03-07 01:25:47 UTC [12345]: [1-1] user=waqar,db=museum,app=psql,client=127.0.0.1 LOG:  message
_PG_STANDARD = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+[A-Z+\d:]+)?)\s+'
    r'\[(?P<pid>\d+)\](?:\s+\S+)?\s+'  # [pid] optional user/db
    r'(?P<severity>LOG|ERROR|FATAL|PANIC|WARNING|NOTICE|INFO|DEBUG\d?):\s+'
    r'(?P<message>.+)$',
    re.IGNORECASE
)

# ── 2. With session context prefix ───────────────────────────────────────────
# 2026-03-07 01:25:47.123 +0500 [12345]: [3-1] user=waqar,db=museum LOG: message
_PG_SESSION = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+[A-Z+\d:]+)?)\s+'
    r'\[(?P<pid>\d+)\]:\s+\[\d+-\d+\]\s+'
    r'user=(?P<user>[^,]+),db=(?P<db>[^,]+)(?:,app=(?P<app>[^,]+))?'
    r'(?:,client=(?P<client>[^\s]+))?\s+'
    r'(?P<severity>LOG|ERROR|FATAL|PANIC|WARNING|NOTICE|INFO|DEBUG\d?):\s+'
    r'(?P<message>.+)$',
    re.IGNORECASE
)

# ── Duration extraction ───────────────────────────────────────────────────────
_DURATION = re.compile(r'duration:\s*([\d.]+)\s*ms', re.IGNORECASE)

# ── Connection/auth events ────────────────────────────────────────────────────
_CONNECT  = re.compile(r'connection received: host=(\S+)\s+port=(\d+)')
_AUTH_OK  = re.compile(r'connection authorized: user=(\S+)\s+database=(\S+)')
_AUTH_FAIL = re.compile(r'(?:password authentication failed|authentication failed)\s+for user "([^"]+)"')
_DISCONNECT = re.compile(r'disconnection: session time: ([\d:]+\.[\d]+)')


def parse_log(log: str) -> dict | None:
    if not log or not log.strip():
        return None

    log = log.strip()

    # Try session-context format first (more specific)
    m = _PG_SESSION.match(log)
    if m:
        d = m.groupdict()
        d['format']  = 'POSTGRESQL_SESSION'
        d['process'] = 'postgresql'
        d['hostname'] = ''
        _enrich(d)
        return d

    # Standard format
    m = _PG_STANDARD.match(log)
    if m:
        d = m.groupdict()
        d['format']   = 'POSTGRESQL'
        d['process']  = 'postgresql'
        d['hostname'] = ''
        d.setdefault('user', '')
        d.setdefault('db', '')
        _enrich(d)
        return d

    return None


def _enrich(d: dict) -> None:
    """Add action tag and extract duration/connection details."""
    msg = d.get('message', '')
    sev = (d.get('severity') or '').upper()

    # Severity → level
    if sev in ('FATAL', 'PANIC', 'ERROR'):
        d['level'] = 'high'
    elif sev == 'WARNING':
        d['level'] = 'mid'
    else:
        d['level'] = 'info'

    # Duration
    m = _DURATION.search(msg)
    if m:
        d['duration_ms'] = float(m.group(1))
        d['action'] = 'SLOW_QUERY' if d['duration_ms'] > 1000 else 'QUERY'
    else:
        d['duration_ms'] = None

    # Connection events
    m = _CONNECT.search(msg)
    if m:
        d['action'] = 'CONNECT'
        d['client_host'] = m.group(1)
        d['client_port'] = m.group(2)
        return

    m = _AUTH_OK.search(msg)
    if m:
        d['action'] = 'AUTH_OK'
        d['user'] = d.get('user') or m.group(1)
        d['db']   = d.get('db')   or m.group(2)
        return

    m = _AUTH_FAIL.search(msg)
    if m:
        d['action'] = 'AUTH_FAIL'
        d['user']   = d.get('user') or m.group(1)
        d['level']  = 'high'
        d['message'] = f"PostgreSQL auth failure for user '{m.group(1)}'"
        return

    m = _DISCONNECT.search(msg)
    if m:
        d['action']       = 'DISCONNECT'
        d['session_time'] = m.group(1)
