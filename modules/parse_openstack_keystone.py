# ============================================================================= (Identity) Log Parser
#
# Handles:
# - Authentication success / failure
# - Token issuance and revocation
# - User / project / role CRUD
# - Role assignment / privilege escalation
# - Policy enforcement failures
# - Service-to-service authentication
#
# Input: Syslog or file-based Keystone log lines
# Output: dict compatible with OpenSIEM parser contract
# =============================================================================

import re


_TS_SYSLOG = re.compile(
    r'^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+keystone\S*:\s+(?P<body>.+)$'
)

_TS_ISO = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+'
    r'\S+\s+keystone\S*:\s+(?P<body>.+)$'
)

AUTH_SUCCESS = re.compile(r'Authentication succeeded|Authorization successful', re.I)
AUTH_FAIL = re.compile(r'Authentication failed|Authorization failed|Invalid token', re.I)

TOKEN_ISSUE = re.compile(r'issued token|token created', re.I)
TOKEN_REVOKE = re.compile(r'revoked token|token revoked', re.I)

USER_CREATE = re.compile(r'Create user|user created', re.I)
USER_DELETE = re.compile(r'Delete user|user deleted', re.I)
PROJECT_CREATE = re.compile(r'Create project|project created', re.I)
PROJECT_DELETE = re.compile(r'Delete project|project deleted', re.I)

ROLE_ASSIGN = re.compile(r'role\s+assignment\s+created|Assign role', re.I)
ROLE_REMOVE = re.compile(r'role\s+assignment\s+deleted|Remove role', re.I)

POLICY_DENY = re.compile(r'policy does not allow|disallowed by policy', re.I)

USER_FIELD = re.compile(r'user(?:_id|=)\s*(?P<user>\S+)', re.I)
PROJECT_FIELD = re.compile(r'project(?:_id|=)\s*(?P<project>\S+)', re.I)
ROLE_FIELD = re.compile(r'role(?:_id|=)\s*(?P<role>\S+)', re.I)
SRC_IP = re.compile(r'(?:from|remote)\s+(?P<ip>\d+\.\d+\.\d+\.\d+)', re.I)


def _extract(rx, text, key):
    m = rx.search(text)
    return m.group(key) if m else ''


def parse_log(log: str) -> dict | None:
    if not log or not log.strip():
        return None

    log = log.strip()

    ts = ''
    host = ''
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
        host = m.group('host')
        body = m.group('body')

    user = _extract(USER_FIELD, body, 'user')
    project = _extract(PROJECT_FIELD, body, 'project')
    role = _extract(ROLE_FIELD, body, 'role')
    src_ip = _extract(SRC_IP, body, 'ip')

    base = {
        'format': 'OPENSTACK_KEYSTONE',
        'timestamp': ts,
        'hostname': host,
        'process': 'keystone',
        'user': user,
        'project': project,
        'role': role,
        'src_ip': src_ip,
        'message': body,
    }

    if AUTH_SUCCESS.search(body):
        base.update({
            'format': 'KEYSTONE_AUTH_SUCCESS',
            'action': 'AUTH_SUCCESS',
            'message': f"Keystone authentication success user={user} src={src_ip}",
        })
        return base

    if AUTH_FAIL.search(body):
        base.update({
            'format': 'KEYSTONE_AUTH_FAILURE',
            'action': 'AUTH_FAILURE',
            'message': f"Keystone authentication failure user={user} src={src_ip}",
        })
        return base

    if TOKEN_ISSUE.search(body):
        base.update({
            'format': 'KEYSTONE_TOKEN_ISSUE',
            'action': 'TOKEN_CREATE',
            'message': f"Keystone token issued user={user} project={project}",
        })
        return base

    if TOKEN_REVOKE.search(body):
        base.update({
            'format': 'KEYSTONE_TOKEN_REVOKE',
            'action': 'TOKEN_REVOKE',
            'message': f"Keystone token revoked user={user}",
        })
        return base

    if USER_CREATE.search(body):
        base.update({
            'format': 'KEYSTONE_USER_CREATE',
            'action': 'CREATE',
            'message': f"Keystone user created user={user}",
        })
        return base

    if USER_DELETE.search(body):
        base.update({
            'format': 'KEYSTONE_USER_DELETE',
            'action': 'DELETE',
            'message': f"Keystone user deleted user={user}",
        })
        return base

    if PROJECT_CREATE.search(body):
        base.update({
            'format': 'KEYSTONE_PROJECT_CREATE',
            'action': 'CREATE',
            'message': f"Keystone project created project={project}",
        })
        return base

    if PROJECT_DELETE.search(body):
        base.update({
            'format': 'KEYSTONE_PROJECT_DELETE',
            'action': 'DELETE',
            'message': f"Keystone project deleted project={project}",
        })
        return base

    if ROLE_ASSIGN.search(body):
        base.update({
            'format': 'KEYSTONE_ROLE_ASSIGN',
            'action': 'ROLE_ASSIGN',
            'message': f"Keystone role assigned user={user} role={role} project={project}",
        })
        return base

    if ROLE_REMOVE.search(body):
        base.update({
            'format': 'KEYSTONE_ROLE_REMOVE',
            'action': 'ROLE_REMOVE',
            'message': f"Keystone role removed user={user} role={role} project={project}",
        })
        return base

    if POLICY_DENY.search(body):
        base.update({
            'format': 'KEYSTONE_POLICY_DENY',
            'action': 'ACCESS_DENIED',
            'message': f"Keystone policy denied user={user} project={project}",
        })
        return base

    return base
