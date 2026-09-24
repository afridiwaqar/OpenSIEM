import re

# =============================================================================
# parse_mysql.py — MySQL / MariaDB Log Parser
#
# Formats handled:
#   1. MySQL General log      (timestamp [Note/Warning/Error] message)
#   2. MySQL Error log        (YYYY-MM-DD HH:MM:SS severity [Note] msg)
#   3. MySQL Slow query log   (# Time / # User@Host / # Query_time ...)
#   4. MariaDB audit plugin   (timestamp,serverhost,user,host,...)
# =============================================================================

# ── 1 & 2. MySQL/MariaDB error/general log ───────────────────────────────────
# 2026-03-07T01:25:47.123456Z 42 [Note] [MY-010931] [Server] message
# 2026-03-07 01:25:47 0 [Warning] message
_MYSQL_ERR = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.\d]+)?(?:Z)?)\s+'
    r'(?P<thread_id>\d+)\s+'
    r'\[(?P<severity>[^\]]+)\]\s+'
    r'(?:\[(?P<code>[^\]]+)\]\s+)?'
    r'(?:\[(?P<subsystem>[^\]]+)\]\s+)?'
    r'(?P<message>.+)$'
)

# ── 3. Slow query log ─────────────────────────────────────────────────────────
# # Time: 2026-03-07T01:25:47.123456Z
# # User@Host: root[root] @ localhost []  Id: 42
# # Query_time: 5.123456  Lock_time: 0.000123 Rows_sent: 1  Rows_examined: 10000
_SLOW_TIME   = re.compile(r'^#\s*Time:\s*(?P<timestamp>\S+)')
_SLOW_USER   = re.compile(r'^#\s*User@Host:\s*(?P<user>\S+)\s*@\s*(?P<host>\S+)')
_SLOW_STATS  = re.compile(
    r'^#\s*Query_time:\s*(?P<query_time>[\d.]+)'
    r'\s+Lock_time:\s*(?P<lock_time>[\d.]+)'
    r'\s+Rows_sent:\s*(?P<rows_sent>\d+)'
    r'\s+Rows_examined:\s*(?P<rows_examined>\d+)'
)

# ── 4. MariaDB Audit plugin ───────────────────────────────────────────────────
# 20260307 01:25:47,serverhost,root,localhost,42,5,QUERY,db_name,'SELECT ...',0
_MARIADB_AUDIT = re.compile(
    r'^(?P<timestamp>\d{8}\s+\d{2}:\d{2}:\d{2}),'
    r'(?P<serverhost>[^,]*),'
    r'(?P<user>[^,]*),'
    r'(?P<host>[^,]*),'
    r'(?P<connection_id>[^,]*),'
    r'(?P<query_id>[^,]*),'
    r'(?P<operation>[^,]*),'
    r'(?P<db>[^,]*),'
    r"(?P<object>'[^']*'|[^,]*),"
    r'(?P<retcode>\d*)'
)


def parse_log(log: str) -> dict | None:
    if not log or not log.strip():
        return None

    log = log.strip()

    # 4. MariaDB Audit
    m = _MARIADB_AUDIT.match(log)
    if m:
        d = m.groupdict()
        d['format']  = 'MARIADB_AUDIT'
        d['process'] = 'mysql'
        d['pid']     = d.get('connection_id', '')
        d['hostname'] = d.get('serverhost', '')
        op  = d.get('operation', '').upper()
        usr = d.get('user', '')
        obj = d.get('object', '').strip("'")
        d['message'] = f"MariaDB {op} user={usr} db={d.get('db','')} query={obj[:80]}"
        return d

    # 1 & 2. MySQL error/general log
    m = _MYSQL_ERR.match(log)
    if m:
        d = m.groupdict()
        d['format']   = 'MYSQL_LOG'
        d['process']  = 'mysqld'
        d['pid']      = d.get('thread_id', '')
        d['hostname'] = ''
        sev = (d.get('severity') or '').lower()
        if sev in ('error', 'fatal'):
            d['level'] = 'high'
        elif sev == 'warning':
            d['level'] = 'mid'
        else:
            d['level'] = 'info'
        return d

    # 3. Slow query log (single-line context lines)
    m = _SLOW_TIME.match(log)
    if m:
        return {
            'format': 'MYSQL_SLOW_TIME', 'process': 'mysqld',
            'timestamp': m.group('timestamp'), 'hostname': '',
            'pid': '', 'message': f"Slow query timestamp: {m.group('timestamp')}"
        }
    m = _SLOW_USER.match(log)
    if m:
        return {
            'format': 'MYSQL_SLOW_USER', 'process': 'mysqld',
            'timestamp': '', 'hostname': '', 'pid': '',
            'user': m.group('user'), 'host': m.group('host'),
            'message': f"Slow query user={m.group('user')} host={m.group('host')}"
        }
    m = _SLOW_STATS.match(log)
    if m:
        d = m.groupdict()
        d.update({'format': 'MYSQL_SLOW_STATS', 'process': 'mysqld',
                  'timestamp': '', 'hostname': '', 'pid': ''})
        d['message'] = (
            f"Slow query time={d['query_time']}s rows_examined={d['rows_examined']}"
        )
        return d

    return None
