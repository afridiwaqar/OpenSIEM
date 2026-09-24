# =============================================================================
# parse_azure_activity.py — Azure Activity Log Parser
#
# Handles:
# - Administrative / Operational events
# - Authentication & authorization failures
# - Resource CRUD operations
# - Role assignments / privilege changes
# - Network / compute / storage control-plane actions
# - Correlation‑ready security summaries
#
# Input: JSON string (Azure Activity Log entry)
# Output: dict compatible with OpenSIEM parser contract
# =============================================================================

import json

AUTH_EVENTS = {
    'Microsoft.Authorization/roleAssignments/write': 'AZURE_ROLE_ASSIGN',
    'Microsoft.Authorization/roleAssignments/delete': 'AZURE_ROLE_REMOVE',
}

RESOURCE_EVENTS = {
    # Compute
    'Microsoft.Compute/virtualMachines/write': 'VM_CREATE_OR_UPDATE',
    'Microsoft.Compute/virtualMachines/delete': 'VM_DELETE',
    'Microsoft.Compute/virtualMachines/start/action': 'VM_START',
    'Microsoft.Compute/virtualMachines/deallocate/action': 'VM_STOP',

    # Network
    'Microsoft.Network/networkInterfaces/write': 'NIC_CREATE_OR_UPDATE',
    'Microsoft.Network/networkSecurityGroups/write': 'NSG_UPDATE',

    # Storage
    'Microsoft.Storage/storageAccounts/write': 'STORAGE_CREATE',
    'Microsoft.Storage/storageAccounts/delete': 'STORAGE_DELETE',
}

AUDIT_CONTROL = {
    'Microsoft.Insights/diagnosticSettings/write': 'LOGGING_MODIFIED',
    'Microsoft.Insights/diagnosticSettings/delete': 'LOGGING_DISABLED',
}

CRUD_PREFIX = {
    'CREATE': ('/write',),
    'DELETE': ('/delete',),
}

def _safe_get(obj, *path):
    for p in path:
        if not isinstance(obj, dict):
            return ''
        obj = obj.get(p)
    return obj or ''


def _classify_crud(operation: str) -> str:
    for crud, suffixes in CRUD_PREFIX.items():
        if any(operation.endswith(s) for s in suffixes):
            return crud
    return ''


def _extract_identity(evt: dict) -> str:
    claims = _safe_get(evt, 'claims')
    if isinstance(claims, dict):
        return claims.get('upn') or claims.get('name') or ''
    return _safe_get(evt, 'caller')


def parse_log(log: str) -> dict | None:
    if not log or not log.strip():
        return None

    try:
        evt = json.loads(log)
    except Exception:
        return None

    operation = _safe_get(evt, 'operationName', 'value')
    status = _safe_get(evt, 'status', 'value')
    sub_status = _safe_get(evt, 'subStatus', 'value')

    user = _extract_identity(evt)
    resource_id = evt.get('resourceId', '')
    event_time = evt.get('eventTimestamp', '')
    correlation_id = evt.get('correlationId', '')
    category = evt.get('category', '')
    caller_ip = evt.get('callerIpAddress', '')

    base = {
        'format': 'AZURE_ACTIVITY',
        'timestamp': event_time,
        'process': 'azure',
        'service': 'activity-log',
        'category': category,
        'operation': operation,
        'crud': _classify_crud(operation),
        'status': status,
        'sub_status': sub_status,
        'user': user,
        'src_ip': caller_ip,
        'resource': resource_id,
        'correlation_id': correlation_id,
        'message': '',
        'raw': evt,
    }

    if operation in AUTH_EVENTS:
        base.update({
            'format': AUTH_EVENTS[operation],
            'message': (
                f"Azure role change {operation.split('/')[-1]} "
                f"user={user} resource={resource_id}"
            ),
        })
        return base

    if operation in RESOURCE_EVENTS:
        base.update({
            'format': f"AZURE_{RESOURCE_EVENTS[operation]}",
            'message': (
                f"Azure resource action {RESOURCE_EVENTS[operation]} "
                f"user={user} resource={resource_id}"
            ),
        })
        return base

    if operation in AUDIT_CONTROL:
        base.update({
            'format': f"AZURE_{AUDIT_CONTROL[operation]}",
            'message': (
                f"Azure logging configuration modified "
                f"by user={user}"
            ),
        })
        return base

    if status and status.lower() != 'succeeded':
        base.update({
            'format': 'AZURE_ACCESS_FAILURE',
            'message': (
                f"Azure operation failed {operation} "
                f"user={user} status={status} ip={caller_ip}"
            ),
        })
        return base

    base['message'] = (
        f"Azure activity {operation} "
        f"user={user} status={status}"
    )
    return base
