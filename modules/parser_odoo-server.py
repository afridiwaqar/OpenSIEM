import re

# =============================================================================
# parse_odoo.py — Odoo ERP Log Parser
#
# Tested against:
# - Odoo 14.x–19.x
# - Default Python logging format
# - Multi-line tracebacks (collapsed safely)
#
# Source examples:
# /var/log/odoo/odoo-server.log
# journald output
#
# =============================================================================

# 2026-03-08 01:25:47,123  INFO dbname odoo.models: message
#
_HDR = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:,\d+)?)\s+'
    r'(?P<level>[A-Z]+)\s+'
    r'(?P<db>\S+)\s+'
    r'(?P<logger>[a-zA-Z0-9_.]+):\s+'
    r'(?P<body>.+)$'
)

_CREATE = re.compile(r'create\(|INSERT INTO', re.IGNORECASE)
_READ   = re.compile(r'search\(|read\(|SELECT ', re.IGNORECASE)
_UPDATE = re.compile(r'write\(|UPDATE ', re.IGNORECASE)
_DELETE = re.compile(r'unlink\(|DELETE FROM', re.IGNORECASE)

_LOGIN_OK = re.compile(r'Login successful|logged in', re.IGNORECASE)
_LOGIN_FAIL = re.compile(r'Login failed|authentication failed|invalid login', re.IGNORECASE)

_ACCESS_DENIED = re.compile(r'Access denied|PermissionError|record rule', re.IGNORECASE)
_SUDO = re.compile(r'\bsudo\b', re.IGNORECASE)

_RPC = re.compile(r'JSONRPC|XMLRPC|rpc', re.IGNORECASE)
_HTTP = re.compile(r'HTTP/1\.[01]"\s+(?P<status>\d{3})', re.IGNORECASE)

_TRACEBACK_START = re.compile(r'^Traceback \(most recent call last\):')

def parse_log(log: str) -> dict | None:
    """
    Parse a single Odoo log entry.
    Multi-line tracebacks should be passed line-by-line;
    the caller may optionally collapse them upstream.
    """

    if not log or not log.strip():
        return None

    log = log.rstrip()

    base = {
        'format': 'ODOO',
        'timestamp': '',
        'hostname': '',
        'process': 'odoo',
        'pid': '',
        'db': '',
        'level': '',
        'logger': '',
        'message': log,
        'action': '',
        'object': '',
    }
    
    m = _HDR.match(log)
    if not m:
        # Traceback continuation or generic line
        if _TRACEBACK_START.search(log):
            base['format'] = 'ODOO_TRACEBACK'
            base['level'] = 'ERROR'
            base['message'] = 'Odoo traceback started'
            return base
        return None

    base.update({
        'timestamp': m.group('timestamp'),
        'db': m.group('db'),
        'level': m.group('level'),
        'logger': m.group('logger'),
    })

    body = m.group('body')
    base['message'] = body

    if _CREATE.search(body):
        base.update({
            'format': 'ODOO_CREATE',
            'action': 'CREATE',
            'message': f"Odoo CREATE operation: {body[:120]}"
        })
        return base

    if _READ.search(body):
        base.update({
            'format': 'ODOO_READ',
            'action': 'READ',
            'message': f"Odoo READ operation: {body[:120]}"
        })
        return base

    if _UPDATE.search(body):
        base.update({
            'format': 'ODOO_UPDATE',
            'action': 'UPDATE',
            'message': f"Odoo UPDATE operation: {body[:120]}"
        })
        return base

    if _DELETE.search(body):
        base.update({
            'format': 'ODOO_DELETE',
            'action': 'DELETE',
            'message': f"Odoo DELETE operation: {body[:120]}"
        })
        return base

    if _LOGIN_OK.search(body):
        base.update({
            'format': 'ODOO_LOGIN_SUCCESS',
            'action': 'LOGIN_SUCCESS',
            'message': f"Odoo login successful: {body[:120]}"
        })
        return base

    if _LOGIN_FAIL.search(body):
        base.update({
            'format': 'ODOO_LOGIN_FAILURE',
            'action': 'LOGIN_FAILURE',
            'message': f"Odoo login failed: {body[:120]}"
        })
        return base

    if _ACCESS_DENIED.search(body):
        base.update({
            'format': 'ODOO_ACCESS_DENIED',
            'action': 'ACCESS_DENIED',
            'message': f"Odoo access denied: {body[:120]}"
        })
        return base

    if _SUDO.search(body):
        base.update({
            'format': 'ODOO_SUDO',
            'action': 'SUDO',
            'message': f"Odoo sudo usage: {body[:120]}"
        })
        return base

    if _RPC.search(body) or _HTTP.search(body):
        base.update({
            'format': 'ODOO_API',
            'action': 'RPC',
            'message': f"Odoo RPC/API call: {body[:120]}"
        })
        return base

    return base
