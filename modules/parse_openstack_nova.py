# =============================================================================
# parse_openstack_nova.py — OpenStack Nova (Compute) Log Parser
#
# Handles:
# - Instance lifecycle (create, start, stop, rebuild, delete)
# - Compute API authorization failures
# - Scheduler / placement decisions
# - Hypervisor-level failures
# - Quota enforcement
# - Security‑relevant operational errors
#
# Input: Syslog or file-based Nova logs
# Output: dict compatible with OpenSIEM parser contract
# =============================================================================

import re


_TS_SYSLOG = re.compile(
    r'^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+nova\S*:\s+(?P<body>.+)$'
)

_TS_ISO = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+'
    r'\S+\s+nova\S*:\s+(?P<body>.+)$'
)


INSTANCE_CREATE = re.compile(r'Create server|instance creating|spawned instance', re.I)
INSTANCE_DELETE = re.compile(r'Delete instance|terminating instance', re.I)
INSTANCE_START = re.compile(r'Start instance|power on', re.I)
INSTANCE_STOP = re.compile(r'Stop instance|power off', re.I)
INSTANCE_REBUILD = re.compile(r'Rebuild instance', re.I)

AUTH_FAIL = re.compile(r'Policy doesn\'t allow|not authorized|Forbidden', re.I)
QUOTA_FAIL = re.compile(r'Quota exceeded|OverQuota', re.I)

SCHEDULER_SELECT = re.compile(r'Selected host|Starting scheduling', re.I)
SCHEDULER_FAIL = re.compile(r'No valid host|Failed to schedule', re.I)

HYPERVISOR_ERROR = re.compile(r'libvirtError|Hypervisor error|VM creation failed', re.I)

INSTANCE_ID = re.compile(r'(instance|server)[ _-]?(id)?[:=]\s*(?P<id>[a-f0-9-]{8,})', re.I)
USER_FIELD = re.compile(r'user(?:_id|=)\s*(?P<user>[a-f0-9-]+)', re.I)
PROJECT_FIELD = re.compile(r'project(?:_id|=)\s*(?P<project>[a-f0-9-]+)', re.I)
HOST_FIELD = re.compile(r'host(?:name|=)\s*(?P<host>\S+)', re.I)


def _extract(rx, text, key):
    m = rx.search(text)
    return m.group(key) if m else ''


def parse_log(log: str) -> dict | None:
    if not log or not log.strip():
        return None

    log = log.strip()
    ts = ''
    hostname = ''
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
        hostname = m.group('host')
        body = m.group('body')

    instance_id = _extract(INSTANCE_ID, body, 'id')
    user = _extract(USER_FIELD, body, 'user')
    project = _extract(PROJECT_FIELD, body, 'project')
    target_host = _extract(HOST_FIELD, body, 'host')

    base = {
        'format': 'OPENSTACK_NOVA',
        'timestamp': ts,
        'hostname': hostname,
        'process': 'nova',
        'instance_id': instance_id,
        'user': user,
        'project': project,
        'target_host': target_host,
        'message': body,
    }

    if INSTANCE_CREATE.search(body):
        base.update({
            'format': 'NOVA_INSTANCE_CREATE',
            'action': 'CREATE',
            'message': f"Nova instance created id={instance_id} project={project}",
        })
        return base

    if INSTANCE_DELETE.search(body):
        base.update({
            'format': 'NOVA_INSTANCE_DELETE',
            'action': 'DELETE',
            'message': f"Nova instance deleted id={instance_id}",
        })
        return base

    if INSTANCE_START.search(body):
        base.update({
            'format': 'NOVA_INSTANCE_START',
            'action': 'START',
            'message': f"Nova instance started id={instance_id}",
        })
        return base

    if INSTANCE_STOP.search(body):
        base.update({
            'format': 'NOVA_INSTANCE_STOP',
            'action': 'STOP',
            'message': f"Nova instance stopped id={instance_id}",
        })
        return base

    if INSTANCE_REBUILD.search(body):
        base.update({
            'format': 'NOVA_INSTANCE_REBUILD',
            'action': 'REBUILD',
            'message': f"Nova instance rebuilt id={instance_id}",
        })
        return base

    if AUTH_FAIL.search(body):
        base.update({
            'format': 'NOVA_AUTH_FAILURE',
            'action': 'ACCESS_DENIED',
            'message': f"Nova authorization failure user={user} project={project}",
        })
        return base

    if QUOTA_FAIL.search(body):
        base.update({
            'format': 'NOVA_QUOTA_EXCEEDED',
            'action': 'QUOTA_EXCEEDED',
            'message': f"Nova quota exceeded user={user} project={project}",
        })
        return base

    if SCHEDULER_SELECT.search(body):
        base.update({
            'format': 'NOVA_SCHEDULER_SELECT',
            'action': 'SCHEDULE',
            'message': f"Nova scheduler selected host {target_host} for instance={instance_id}",
        })
        return base

    if SCHEDULER_FAIL.search(body):
        base.update({
            'format': 'NOVA_SCHEDULER_FAILURE',
            'action': 'SCHEDULE_FAIL',
            'message': f"Nova scheduler failed for instance={instance_id}",
        })
        return base

    if HYPERVISOR_ERROR.search(body):
        base.update({
            'format': 'NOVA_HYPERVISOR_ERROR',
            'action': 'HYPERVISOR_ERROR',
            'message': f"Nova hypervisor error instance={instance_id} host={target_host}",
        })
        return base

    return base
