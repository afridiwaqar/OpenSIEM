# =============================================================================
# parse_openstack_neutron.py — OpenStack Neutron (Networking) Log Parser
#
# Handles:
# - Network / subnet CRUD
# - Port creation, update, deletion
# - Security group rule changes
# - Router attach/detach
# - Policy / authorization failures
# - RPC and agent‑side operational errors
#
# Input: Syslog or file-based Neutron logs
# Output: dict compatible with OpenSIEM parser contract
# =============================================================================

import re


_TS_SYSLOG = re.compile(
    r'^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+neutron\S*:\s+(?P<body>.+)$'
)

_TS_ISO = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+'
    r'\S+\s+neutron\S*:\s+(?P<body>.+)$'
)


NET_CREATE = re.compile(r'Create network|network created', re.I)
NET_DELETE = re.compile(r'Delete network|network deleted', re.I)

SUBNET_CREATE = re.compile(r'Create subnet|subnet created', re.I)
SUBNET_DELETE = re.compile(r'Delete subnet|subnet deleted', re.I)

PORT_CREATE = re.compile(r'Create port|port created', re.I)
PORT_UPDATE = re.compile(r'Update port|port updated', re.I)
PORT_DELETE = re.compile(r'Delete port|port deleted', re.I)

ROUTER_ATTACH = re.compile(r'Add interface to router|interface attached', re.I)
ROUTER_DETACH = re.compile(r'Remove interface from router|interface detached', re.I)

SECGRP_RULE_ADD = re.compile(r'Create security group rule|rule added', re.I)
SECGRP_RULE_DEL = re.compile(r'Delete security group rule|rule removed', re.I)

POLICY_DENY = re.compile(r'Policy doesn\'t allow|not authorized|Forbidden', re.I)
RPC_ERROR = re.compile(r'RPC Error|MessagingTimeout|AMQPTimeout', re.I)
AGENT_ERROR = re.compile(r'Agent failed|failed to apply|OVS error', re.I)

NET_ID = re.compile(r'network(?:_id|=)\s*(?P<id>[a-f0-9-]+)', re.I)
SUBNET_ID = re.compile(r'subnet(?:_id|=)\s*(?P<id>[a-f0-9-]+)', re.I)
PORT_ID = re.compile(r'port(?:_id|=)\s*(?P<id>[a-f0-9-]+)', re.I)
ROUTER_ID = re.compile(r'router(?:_id|=)\s*(?P<id>[a-f0-9-]+)', re.I)
SECGRP_ID = re.compile(r'security group(?:_id|=)\s*(?P<id>[a-f0-9-]+)', re.I)

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

    network = _extract(NET_ID, body, 'id')
    subnet = _extract(SUBNET_ID, body, 'id')
    port = _extract(PORT_ID, body, 'id')
    router = _extract(ROUTER_ID, body, 'id')
    secgrp = _extract(SECGRP_ID, body, 'id')
    user = _extract(USER_FIELD, body, 'user')
    project = _extract(PROJECT_FIELD, body, 'project')
    target_host = _extract(HOST_FIELD, body, 'host')

    base = {
        'format': 'OPENSTACK_NEUTRON',
        'timestamp': ts,
        'hostname': hostname,
        'process': 'neutron',
        'user': user,
        'project': project,
        'network_id': network,
        'subnet_id': subnet,
        'port_id': port,
        'router_id': router,
        'security_group': secgrp,
        'target_host': target_host,
        'message': body,
    }

    if NET_CREATE.search(body):
        base.update({
            'format': 'NEUTRON_NETWORK_CREATE',
            'action': 'CREATE',
            'message': f"Neutron network created id={network}",
        })
        return base

    if NET_DELETE.search(body):
        base.update({
            'format': 'NEUTRON_NETWORK_DELETE',
            'action': 'DELETE',
            'message': f"Neutron network deleted id={network}",
        })
        return base

    if SUBNET_CREATE.search(body):
        base.update({
            'format': 'NEUTRON_SUBNET_CREATE',
            'action': 'CREATE',
            'message': f"Neutron subnet created id={subnet}",
        })
        return base

    if SUBNET_DELETE.search(body):
        base.update({
            'format': 'NEUTRON_SUBNET_DELETE',
            'action': 'DELETE',
            'message': f"Neutron subnet deleted id={subnet}",
        })
        return base

    if PORT_CREATE.search(body):
        base.update({
            'format': 'NEUTRON_PORT_CREATE',
            'action': 'CREATE',
            'message': f"Neutron port created id={port}",
        })
        return base

    if PORT_UPDATE.search(body):
        base.update({
            'format': 'NEUTRON_PORT_UPDATE',
            'action': 'UPDATE',
            'message': f"Neutron port updated id={port}",
        })
        return base

    if PORT_DELETE.search(body):
        base.update({
            'format': 'NEUTRON_PORT_DELETE',
            'action': 'DELETE',
            'message': f"Neutron port deleted id={port}",
        })
        return base

    if ROUTER_ATTACH.search(body):
        base.update({
            'format': 'NEUTRON_ROUTER_ATTACH',
            'action': 'ATTACH',
            'message': f"Neutron router interface attached router={router} subnet={subnet}",
        })
        return base

    if ROUTER_DETACH.search(body):
        base.update({
            'format': 'NEUTRON_ROUTER_DETACH',
            'action': 'DETACH',
            'message': f"Neutron router interface detached router={router}",
        })
        return base

    if SECGRP_RULE_ADD.search(body):
        base.update({
            'format': 'NEUTRON_SECGRP_RULE_ADD',
            'action': 'UPDATE',
            'message': f"Neutron security group rule added group={secgrp}",
        })
        return base

    if SECGRP_RULE_DEL.search(body):
        base.update({
            'format': 'NEUTRON_SECGRP_RULE_DELETE',
            'action': 'UPDATE',
            'message': f"Neutron security group rule removed group={secgrp}",
        })
        return base

    if POLICY_DENY.search(body):
        base.update({
            'format': 'NEUTRON_POLICY_DENY',
            'action': 'ACCESS_DENIED',
            'message': f"Neutron policy denied user={user} project={project}",
        })
        return base

    if RPC_ERROR.search(body):
        base.update({
            'format': 'NEUTRON_RPC_ERROR',
            'action': 'RPC_ERROR',
            'message': f"Neutron RPC error host={target_host} port={port}",
        })
        return base

    if AGENT_ERROR.search(body):
        base.update({
            'format': 'NEUTRON_AGENT_ERROR',
            'action': 'AGENT_ERROR',
            'message': f"Neutron agent error host={target_host}",
        })
        return base

    return base
