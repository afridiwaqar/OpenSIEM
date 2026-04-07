import re

# =============================================================================
# parse_moodle.py — Moodle LMS Log Parser
#
# Tested with:
# - Moodle 3.9 – 4.x
# - logstore_standard_log entries
# - Web server access logs (PHP front controller)
# - PHP error / exception logs
#
# Log Sources:
#   /var/log/moodle/moodle.log
#   /var/log/apache2/access.log (Moodle context)
#   /var/log/php*/error.log
#
# =============================================================================
#
# Detection Domains:
# - Authentication / session management
# - Authorization / capability violations
# - CRUD on core objects (users, courses, activities, grades)
# - Administrative actions
# - PHP exceptions & security errors
#
# =============================================================================

# -----------------------------------------------------------------------------
# Moodle standard logstore entry (text export / debug)
# -----------------------------------------------------------------------------
# 2026-03-07 01:25:47 INFO eventname=\core\event\user_loggedin userid=5 courseid=0
#
_LOGSTORE = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+'
    r'(?P<level>[A-Z]+)\s+'
    r'(?P<body>.+)$'
)

_KV = re.compile(r'(\w+)=([^\s]+)')

_LOGIN_OK = re.compile(
    r'user_loggedin|login\s+succeeded', re.I
)
_LOGIN_FAIL = re.compile(
    r'login\s+failed|invalid\s+password|authentication\s+failed', re.I
)
_LOGOUT = re.compile(
    r'user_loggedout', re.I
)

_CAP_DENIED = re.compile(
    r'capability\s+violation|permission\s+denied|access\s+denied', re.I
)

_CREATE = re.compile(
    r'(created|\\event\\.*created)', re.I
)
_READ = re.compile(
    r'(viewed|accessed|\\event\\.*viewed)', re.I
)
_UPDATE = re.compile(
    r'(updated|modified|\\event\\.*updated)', re.I
)
_DELETE = re.compile(
    r'(deleted|removed|\\event\\.*deleted)', re.I
)

_USER = re.compile(r'userid=(\d+)')
_TARGET_USER = re.compile(r'relateduserid=(\d+)')
_COURSE = re.compile(r'courseid=(\d+)')
_CONTEXT = re.compile(r'contextinstanceid=(\d+)')
_OBJECT = re.compile(r'objecttable=([a-z0-9_]+)', re.I)

_ADMIN = re.compile(
    r'(config|course_created|course_deleted|user_created|user_deleted|role_assigned)', re.I
)

_PHP_FATAL = re.compile(
    r'PHP Fatal error|Uncaught exception|Stack trace:', re.I
)

_HTTP = re.compile(
    r'"(GET|POST|PUT|DELETE)\s+([^\s?]+).*"\s+(?P<status>\d{3})'
)

def _parse_kv(text: str) -> dict:
    """Extract Moodle key=value fields into a dict."""
    kv = {}
    for k, v in _KV.findall(text):
        kv[k] = v
    return kv

def parse_log(log: str) -> dict | None:
    if not log or not log.strip():
        return None

    log = log.rstrip()

    base = {
        'format': 'MOODLE',
        'timestamp': '',
        'hostname': '',
        'process': 'moodle',
        'pid': '',
        'level': '',
        'user': '',
        'target_user': '',
        'course_id': '',
        'object': '',
        'action': '',
        'message': log,
    }

    if _PHP_FATAL.search(log):
        base.update({
            'format': 'MOODLE_PHP_ERROR',
            'level': 'ERROR',
            'action': 'EXCEPTION',
            'message': 'Moodle PHP fatal error or exception detected'
        })
        return base

    m = _LOGSTORE.match(log)
    if m:
        body = m.group('body')
        base.update({
            'timestamp': m.group('timestamp'),
            'level': m.group('level'),
            'message': body,
        })

        kv = _parse_kv(body)

        base['user'] = kv.get('userid', '')
        base['target_user'] = kv.get('relateduserid', '')
        base['course_id'] = kv.get('courseid', '')
        base['object'] = kv.get('objecttable', '')

        if _LOGIN_OK.search(body):
            base.update({
                'format': 'MOODLE_LOGIN_SUCCESS',
                'action': 'LOGIN_SUCCESS',
                'message': f"Moodle login successful user={base['user']}"
            })
            return base

        if _LOGIN_FAIL.search(body):
            base.update({
                'format': 'MOODLE_LOGIN_FAILURE',
                'action': 'LOGIN_FAILURE',
                'message': f"Moodle login failed user={base['user']}"
            })
            return base

        if _LOGOUT.search(body):
            base.update({
                'format': 'MOODLE_LOGOUT',
                'action': 'LOGOUT',
                'message': f"Moodle logout user={base['user']}"
            })
            return base

        if _CAP_DENIED.search(body):
            base.update({
                'format': 'MOODLE_ACCESS_DENIED',
                'action': 'ACCESS_DENIED',
                'message': (
                    f"Moodle capability violation user={base['user']} "
                    f"course={base['course_id']}"
                )
            })
            return base

        if _CREATE.search(body):
            base.update({
                'format': 'MOODLE_CREATE',
                'action': 'CREATE',
                'message': (
                    f"Moodle CREATE object={base['object']} "
                    f"user={base['user']} course={base['course_id']}"
                )
            })
            return base

        if _READ.search(body):
            base.update({
                'format': 'MOODLE_READ',
                'action': 'READ',
                'message': (
                    f"Moodle READ object={base['object']} "
                    f"user={base['user']} course={base['course_id']}"
                )
            })
            return base

        if _UPDATE.search(body):
            base.update({
                'format': 'MOODLE_UPDATE',
                'action': 'UPDATE',
                'message': (
                    f"Moodle UPDATE object={base['object']} "
                    f"user={base['user']} course={base['course_id']}"
                )
            })
            return base

        if _DELETE.search(body):
            base.update({
                'format': 'MOODLE_DELETE',
                'action': 'DELETE',
                'message': (
                    f"Moodle DELETE object={base['object']} "
                    f"user={base['user']} course={base['course_id']}"
                )
            })
            return base

        if _ADMIN.search(body):
            base.update({
                'format': 'MOODLE_ADMIN',
                'action': 'ADMIN',
                'message': f"Moodle administrative action user={base['user']}"
            })
            return base

        return base

    mh = _HTTP.search(log)
    if mh:
        base.update({
            'format': 'MOODLE_HTTP',
            'action': 'HTTP',
            'message': (
                f"Moodle HTTP {mh.group(1)} {mh.group(2)} "
                f"status={mh.group('status')}"
            )
        })
        return base

    return None
