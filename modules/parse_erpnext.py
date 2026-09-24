import re

# =============================================================================
# parse_erpnext.py — ERPNext / Frappe Log Parser
#
# Tested against:
# - ERPNext 13.x – 15.x
# - Frappe framework logging
# - File logs and journald output
#
# Log sources:
#   /var/log/erpnext/erpnext.log
#   /var/log/frappe/frappe.log
#
# =============================================================================
#
# Core Detection Categories:
# - Authentication (login success/failure)
# - Authorization (permission denied)
# - CRUD operations (Doctype-level)
# - HTTP / RPC calls
# - Administrative actions
# - Exceptions & tracebacks
#
# Return contract (OpenSIEM standard):
#   format, timestamp, hostname, process, pid, message
#   + ERP-specific enrichment fields
#
# =============================================================================

# -----------------------------------------------------------------------------
# Standard ERPNext log header
# -----------------------------------------------------------------------------
# 2026-03-08 01:25:47,123 INFO [module] message
#
_HDR = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\s+'
    r'(?P<level>[A-Z]+)\s+'
    r'\[(?P<module}[^\]]+)\]\s+'
    r'(?P<body>.+)$'
)

_LOGIN_OK = re.compile(
    r'(login successful|logged in)', re.IGNORECASE
)
_LOGIN_FAIL = re.compile(
    r'(failed login|authentication failed|invalid login)', re.IGNORECASE
)

_PERMISSION_DENIED = re.compile(
    r'(permission denied|not permitted|insufficient privilege)', re.IGNORECASE
)

_CREATE = re.compile(
    r'(INSERT INTO|create\s+\w+|New\s+\w+\s+created)', re.IGNORECASE
)
_READ = re.compile(
    r'(SELECT\s+|read\s+\w+|fetching\s+document)', re.IGNORECASE
)
_UPDATE = re.compile(
    r'(UPDATE\s+|write\s+\w+|saved\s+\w+)', re.IGNORECASE
)
_DELETE = re.compile(
    r'(DELETE FROM|unlink\s+\w+|deleted\s+\w+)', re.IGNORECASE
)

_DOCTYPE = re.compile(
    r'Doctype\s+([A-Za-z0-9_ ]+)', re.IGNORECASE
)

_USER = re.compile(
    r'user\s*=\s*([A-Za-z0-9@._-]+)', re.IGNORECASE
)

_HTTP = re.compile(
    r'HTTP/\d\.\d"\s+(?P<status>\d{3})', re.IGNORECASE
)
_RPC = re.compile(
    r'(RPC|JSONRPC|frappe\.handler)', re.IGNORECASE
)

_ADMIN = re.compile(
    r'(install|uninstall|migrate|bench|patch)', re.IGNORECASE
)

_TRACEBACK_START = re.compile(r'^Traceback \(most recent call last\):')

def parse_log(log: str) -> dict | None:
    if not log or not log.strip():
        return None

    log = log.rstrip()

    base = {
        'format': 'ERPNEXT',
        'timestamp': '',
        'hostname': '',
        'process': 'erpnext',
        'pid': '',
        'level': '',
        'module': '',
        'user': '',
        'doctype': '',
        'action': '',
        'message': log,
    }

    if _TRACEBACK_START.match(log):
        base.update({
            'format': 'ERPNEXT_TRACEBACK',
            'level': 'ERROR',
            'action': 'EXCEPTION',
            'message': 'ERPNext Python traceback started'
        })
        return base

    m = _HDR.match(log)
    if not m:
        # Non-standard line; ignore safely
        return None

    body = m.group('body')
    base.update({
        'timestamp': m.group('timestamp'),
        'level': m.group('level'),
        'module': m.group('module'),
        'message': body
    })

    # Extract optional fields
    mu = _USER.search(body)
    if mu:
        base['user'] = mu.group(1)

    md = _DOCTYPE.search(body)
    if md:
        base['doctype'] = md.group(1).strip()

    if _LOGIN_OK.search(body):
        base.update({
            'format': 'ERPNEXT_LOGIN_SUCCESS',
            'action': 'LOGIN_SUCCESS',
            'message': f"ERPNext login successful user={base['user']}"
        })
        return base

    if _LOGIN_FAIL.search(body):
        base.update({
            'format': 'ERPNEXT_LOGIN_FAILURE',
            'action': 'LOGIN_FAILURE',
            'message': f"ERPNext login failed user={base['user']}"
        })
        return base

    if _PERMISSION_DENIED.search(body):
        base.update({
            'format': 'ERPNEXT_PERMISSION_DENIED',
            'action': 'ACCESS_DENIED',
            'message': (
                f"ERPNext permission denied user={base['user']} "
                f"doctype={base['doctype']}"
            )
        })
        return base

    if _CREATE.search(body):
        base.update({
            'format': 'ERPNEXT_CREATE',
            'action': 'CREATE',
            'message': (
                f"ERPNext CREATE doctype={base['doctype']} user={base['user']}"
            )
        })
        return base

    if _READ.search(body):
        base.update({
            'format': 'ERPNEXT_READ',
            'action': 'READ',
            'message': (
                f"ERPNext READ doctype={base['doctype']} user={base['user']}"
            )
        })
        return base

    if _UPDATE.search(body):
        base.update({
            'format': 'ERPNEXT_UPDATE',
            'action': 'UPDATE',
            'message': (
                f"ERPNext UPDATE doctype={base['doctype']} user={base['user']}"
            )
        })
        return base

    if _DELETE.search(body):
        base.update({
            'format': 'ERPNEXT_DELETE',
            'action': 'DELETE',
            'message': (
                f"ERPNext DELETE doctype={base['doctype']} user={base['user']}"
            )
        })
        return base

    if _RPC.search(body) or _HTTP.search(body):
        base.update({
            'format': 'ERPNEXT_RPC',
            'action': 'RPC',
            'message': f"ERPNext RPC/API activity user={base['user']}"
        })
        return base

    if _ADMIN.search(body):
        base.update({
            'format': 'ERPNEXT_ADMIN',
            'action': 'ADMIN',
            'message': f"ERPNext administrative action by user={base['user']}"
        })
        return base

    return base
