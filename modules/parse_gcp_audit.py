import json
import re
from datetime import datetime

# =============================================================================
# parse_gcp_audit.py — Google Cloud Platform Audit Log Parser
#
# Supported log types:
# - Admin Activity
# - Data Access
# - System Event
# - Policy / IAM changes
#
# Supports CRUD-style classification, authentication, authorization,
# administrative changes, and error conditions.
#
# Input format:
# - JSON (Cloud Logging export, Pub/Sub, Ops Agent, Filesink)
#
# Output:
# - Normalized OpenSIEM event dict, correlation-ready
# =============================================================================

# Common operation classifications
_CREATE = re.compile(r'(create|insert|add)', re.IGNORECASE)
_READ   = re.compile(r'(get|list|read|fetch)', re.IGNORECASE)
_UPDATE = re.compile(r'(update|set|patch|write)', re.IGNORECASE)
_DELETE = re.compile(r'(delete|remove|destroy)', re.IGNORECASE)

# Auth / IAM semantics
_LOGIN = re.compile(r'Login|Authenticate', re.IGNORECASE)
_DENY = re.compile(r'deny|permissionDenied|unauthorized', re.IGNORECASE)
_IAM = re.compile(r'iam\.|setIamPolicy|roles/', re.IGNORECASE)

# Network / API usage
_API = re.compile(r'google\.|api', re.IGNORECASE)
_ADMIN = re.compile(r'admin|policy|setIamPolicy|createRole', re.IGNORECASE)


def _safe_get(d, *keys, default=''):
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k)
    return d if d is not None else default


def parse_log(log: str) -> dict | None:
    if not log or not log.strip():
        return None

    try:
        evt = json.loads(log)
    except Exception:
        return None

    proto = evt.get('protoPayload', {})
    auth = proto.get('authenticationInfo', {})
    req = proto.get('requestMetadata', {})
    status = proto.get('status', {})

    method = proto.get('methodName', '')
    service = proto.get('serviceName', '')
    resource = _safe_get(proto, 'resourceName')
    principal = auth.get('principalEmail', '')
    src_ip = req.get('callerIp', '')

    base = {
        'format': 'GCP_AUDIT',
        'timestamp': evt.get('timestamp', ''),
        'hostname': '',
        'process': 'gcp',
        'pid': '',
        'user': principal,
        'src_ip': src_ip,
        'service': service,
        'method': method,
        'resource': resource,
        'action': '',
        'severity': evt.get('severity', ''),
        'message': '',
    }

    # Authentication / login-like events
    if _LOGIN.search(method):
        if status:
            base.update({
                'format': 'GCP_AUTH_FAILURE',
                'action': 'LOGIN_FAILURE',
                'message': f"GCP authentication failed user={principal} service={service}",
            })
        else:
            base.update({
                'format': 'GCP_AUTH_SUCCESS',
                'action': 'LOGIN_SUCCESS',
                'message': f"GCP authentication success user={principal} service={service}",
            })
        return base

    # Authorization failures
    if status and _DENY.search(str(status)):
        base.update({
            'format': 'GCP_ACCESS_DENIED',
            'action': 'ACCESS_DENIED',
            'message': f"GCP access denied user={principal} method={method}",
        })
        return base

    # IAM / Policy changes
    if _IAM.search(method) or _ADMIN.search(method):
        base.update({
            'format': 'GCP_IAM_ADMIN',
            'action': 'ADMIN',
            'message': f"GCP IAM change {method} by {principal}",
        })
        return base

    # CRUD-style classification
    if _CREATE.search(method):
        base.update({
            'format': 'GCP_CREATE',
            'action': 'CREATE',
            'message': f"GCP CREATE {resource} by {principal}",
        })
        return base

    if _READ.search(method):
        base.update({
            'format': 'GCP_READ',
            'action': 'READ',
            'message': f"GCP READ {resource} by {principal}",
        })
        return base

    if _UPDATE.search(method):
        base.update({
            'format': 'GCP_UPDATE',
            'action': 'UPDATE',
            'message': f"GCP UPDATE {resource} by {principal}",
        })
        return base

    if _DELETE.search(method):
        base.update({
            'format': 'GCP_DELETE',
            'action': 'DELETE',
            'message': f"GCP DELETE {resource} by {principal}",
        })
        return base

    # API / service usage
    if _API.search(service):
        base.update({
            'format': 'GCP_API_CALL',
            'action': 'API',
            'message': f"GCP API call {method} by {principal}",
        })
        return base

    # Fallback
    base['message'] = f"GCP Audit event {method} user={principal}"
    return base
