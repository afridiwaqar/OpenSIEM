# =============================================================================
# parse_login_accounting.py — Linux Login Accounting Parser
#
# Handles:
# - Successful logins (wtmp / last)
# - Failed logins (btmp / lastb)
# - Session termination and still-active sessions
# - Remote vs local access (SSH, console, tty)
# - Brute-force indicators from repeated failures
# - faillog-style aggregate failure counters
#
# Input:
# - Output lines from `last`
# - Output lines from `lastb`
# - Output lines from `faillog`
#
# Output: dict compatible with OpenSIEM parser contract
# =============================================================================

import re


LAST_SUCCESS = re.compile(
    r'^(?P<user>\S+)\s+'
    r'(?P<tty>\S+)\s+'
    r'(?P<src>\S+)\s+'
    r'(?P<start>\w+\s+\w+\s+\d+\s+\d{2}:\d{2})'
    r'(?:\s+-\s+(?P<end>\d{2}:\d{2})|\s+still logged in)',
    re.I
)

LAST_FAILURE = re.compile(
    r'^(?P<user>\S+)\s+'
    r'(?P<tty>\S+)\s+'
    r'(?P<src>\S+)\s+'
    r'(?P<time>\w+\s+\w+\s+\d+\s+\d{2}:\d{2})',
    re.I
)

FAILLOG = re.compile(
    r'^(?P<user>\S+)\s+'
    r'(?P<count>\d+)\s+'
    r'(?P<last>\S+)',
    re.I
)


def _normalize_src(src: str) -> str:
    if src in ('-', 'tty', 'console', 'local'):
        return ''
    return src


def parse_log(log: str) -> dict | None:
    if not log or not log.strip():
        return None

    log = log.strip()

    m = LAST_SUCCESS.match(log)
    if m:
        src = _normalize_src(m.group('src'))
        user = m.group('user')
        tty = m.group('tty')
        start = m.group('start')
        end = m.group('end')

        base = {
            'process': 'login',
            'user': user,
            'tty': tty,
            'src_ip': src,
            'timestamp': start,
            'message': '',
        }

        if end:
            base.update({
                'format': 'LOGIN_SESSION_CLOSED',
                'action': 'SESSION_CLOSED',
                'message': (
                    f"User session closed "
                    f"user={user} tty={tty}"
                ),
            })
            return base

        base.update({
            'format': 'LOGIN_SUCCESS',
            'action': 'LOGIN_SUCCESS',
            'message': (
                f"User login successful "
                f"user={user} src={src or 'LOCAL'} tty={tty}"
            ),
        })
        return base

    m = LAST_FAILURE.match(log)
    if m:
        src = _normalize_src(m.group('src'))
        user = m.group('user')
        tty = m.group('tty')
        t = m.group('time')

        return {
            'format': 'LOGIN_FAILURE',
            'process': 'login',
            'timestamp': t,
            'user': user,
            'tty': tty,
            'src_ip': src,
            'action': 'LOGIN_FAILURE',
            'message': (
                f"User login failed "
                f"user={user} src={src or 'LOCAL'} tty={tty}"
            ),
        }

    m = FAILLOG.match(log)
    if m:
        user = m.group('user')
        count = int(m.group('count'))
        last = m.group('last')

        severity = 'LOW'
        if count >= 5:
            severity = 'MEDIUM'
        if count >= 10:
            severity = 'HIGH'

        return {
            'format': 'LOGIN_FAILURE_AGGREGATE',
            'process': 'login',
            'timestamp': '',
            'user': user,
            'failures': count,
            'last_failure': last,
            'action': 'FAILURE_COUNT',
            'severity': severity,
            'message': (
                f"Repeated login failures "
                f"user={user} count={count} last={last}"
            ),
        }

    return None
