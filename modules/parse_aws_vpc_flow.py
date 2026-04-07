# =============================================================================
# parse_aws_vpc_flow.py — AWS VPC Flow Log Parser
#
# Supports:
# - Versions 2, 3, 4, 5
# - IPv4 / IPv6
# - ACCEPT / REJECT semantics
# - Network behavior classification
#
# Output is correlation‑ready and security‑focused.
# =============================================================================

def _safe_int(v):
    try:
        return int(v)
    except Exception:
        return 0


def _protocol_name(proto):
    return {
        '1': 'ICMP',
        '6': 'TCP',
        '17': 'UDP',
    }.get(proto, proto)


def _classify_behavior(rec):
    """
    Derive security‑meaningful behavior from flow attributes.
    """
    if rec['action'] == 'REJECT':
        if rec['dst_port'] in (22, 3389):
            return 'BLOCKED_REMOTE_ACCESS'
        if rec['dst_port'] in (3306, 5432, 27017):
            return 'BLOCKED_DB_ACCESS'
        return 'BLOCKED_TRAFFIC'

    # ACCEPT cases
    if rec['bytes'] > 10_000_000:
        return 'LARGE_DATA_TRANSFER'

    if rec['dst_port'] in (22, 3389):
        return 'REMOTE_ACCESS'

    if rec['dst_port'] in (80, 443):
        return 'WEB_ACCESS'

    if rec['dst_port'] in (53,):
        return 'DNS_TRAFFIC'

    if rec['proto_name'] == 'ICMP':
        return 'ICMP_TRAFFIC'

    return 'GENERIC_NETWORK'


def parse_log(log: str) -> dict | None:
    """
    Parse one AWS VPC Flow Log line.
    Returns OpenSIEM‑compatible event dict or None.
    """

    if not log or not log.strip():
        return None

    parts = log.strip().split()
    if len(parts) < 14:
        return None  # invalid / truncated

    rec = {
        'version': parts[0],
        'account_id': parts[1],
        'interface_id': parts[2],
        'src_ip': parts[3],
        'dst_ip': parts[4],
        'src_port': _safe_int(parts[5]),
        'dst_port': _safe_int(parts[6]),
        'protocol': parts[7],
        'packets': _safe_int(parts[8]),
        'bytes': _safe_int(parts[9]),
        'start': parts[10],
        'end': parts[11],
        'action': parts[12],
        'log_status': parts[13],
    }

    rec['proto_name'] = _protocol_name(rec['protocol'])

    # ----- Extended fields (v3+) -----
    idx = 14
    if len(parts) > idx:
        rec['tcp_flags'] = parts[idx]
        idx += 1
    if len(parts) > idx:
        rec['flow_type'] = parts[idx]
        idx += 1
    if len(parts) > idx:
        rec['region'] = parts[idx]
        idx += 1
    if len(parts) > idx:
        rec['az'] = parts[idx]
        idx += 1

    behavior = _classify_behavior(rec)

    base = {
        'format': 'AWS_VPC_FLOW',
        'timestamp': rec.get('start'),
        'process': 'aws',
        'service': 'vpc-flow',
        'account_id': rec['account_id'],
        'interface_id': rec['interface_id'],
        'src_ip': rec['src_ip'],
        'dst_ip': rec['dst_ip'],
        'src_port': rec['src_port'],
        'dst_port': rec['dst_port'],
        'protocol': rec['proto_name'],
        'action': rec['action'],
        'packets': rec['packets'],
        'bytes': rec['bytes'],
        'region': rec.get('region', ''),
        'az': rec.get('az', ''),
        'behavior': behavior,
        'raw': rec,
    }

    if rec['action'] == 'REJECT':
        base['format'] = 'AWS_VPC_FLOW_REJECT'
        base['message'] = (
            f"VPC blocked {rec['proto_name']} "
            f"{rec['src_ip']}:{rec['src_port']} → "
            f"{rec['dst_ip']}:{rec['dst_port']}"
        )
        return base

    # ACCEPT
    if behavior == 'LARGE_DATA_TRANSFER':
        base['format'] = 'AWS_VPC_FLOW_LARGE_TRANSFER'
        base['message'] = (
            f"Large data transfer {rec['bytes']} bytes "
            f"{rec['src_ip']} → {rec['dst_ip']}"
        )
        return base

    if behavior == 'REMOTE_ACCESS':
        base['format'] = 'AWS_VPC_FLOW_REMOTE_ACCESS'
        base['message'] = (
            f"Remote access {rec['proto_name']} "
            f"{rec['src_ip']} → {rec['dst_ip']}:{rec['dst_port']}"
        )
        return base

    if behavior == 'WEB_ACCESS':
        base['format'] = 'AWS_VPC_FLOW_WEB'
        base['message'] = (
            f"Web traffic {rec['src_ip']} → {rec['dst_ip']}:{rec['dst_port']}"
        )
        return base

    # Generic ACCEPT
    base['format'] = 'AWS_VPC_FLOW_ACCEPT'
    base['message'] = (
        f"VPC allowed {rec['proto_name']} "
        f"{rec['src_ip']}:{rec['src_port']} → "
        f"{rec['dst_ip']}:{rec['dst_port']}"
    )
    return base
