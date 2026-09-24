import re

# =============================================================================
# parse_firewall.py — Linux Firewall Log Parser (iptables / nftables / ufw)
#
# Formats handled:
#   1. iptables/nftables kernel log  (IN= OUT= SRC= DST= ...)
#   2. UFW allow/block               (UFW BLOCK IN= OUT= ...)
#   3. firewalld rich rule           (FINAL_REJECT / ACCEPT, same kv format)
# =============================================================================

# ── 1. iptables / nftables kernel log ────────────────────────────────────────
# Mar  7 01:25:47 hostname kernel: [12345.678] IPTABLES-DROP: IN=eth0 OUT= ...
# 2026-03-07T01:25:47+05:00 hostname kernel: FORWARD drop: IN=eth0 OUT=eth1 ...
_IPTABLES = re.compile(
    r'(?:^|\s)(?:IN=(?P<in_iface>\S*))?\s*'
    r'(?:OUT=(?P<out_iface>\S*))?\s*'
    r'(?:MAC=(?P<mac>\S*))?\s*'
    r'(?:SRC=(?P<src_ip>[\d.]+))?\s*'
    r'(?:DST=(?P<dst_ip>[\d.]+))?\s*'
    r'(?:LEN=(?P<length>\d+))?\s*'
    r'(?:.*?)?'
    r'(?:PROTO=(?P<proto>\S+))?\s*'
    r'(?:SPT=(?P<src_port>\d+))?\s*'
    r'(?:DPT=(?P<dst_port>\d+))?',
    re.IGNORECASE
)

# Syslog wrapper that arrives before the kv payload
_SYSLOG_WRAP = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\S+|[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+kernel:\s*'
    r'(?:\[\s*[\d.]+\]\s*)?'          # optional [uptime]
    r'(?P<chain>[A-Z0-9_\-]+):\s*'    # chain/prefix label e.g. UFW BLOCK
    r'(?P<kvpayload>.+)$'
)

# UFW variant (has two-word prefix "UFW BLOCK" or "UFW ALLOW")
_UFW = re.compile(
    r'UFW\s+(?P<action>BLOCK|ALLOW|AUDIT|LIMIT)',
    re.IGNORECASE
)


def _parse_kv(payload: str) -> dict:
    """Extract iptables-style KEY=VALUE pairs from a string."""
    result = {}
    for m in re.finditer(r'(\w+)=([\S]*)', payload):
        result[m.group(1).lower()] = m.group(2)
    return result


def parse_log(log: str) -> dict | None:
    if not log or not log.strip():
        return None

    log = log.strip()
    result = {
        'format': 'UNKNOWN',
        'timestamp': '', 'hostname': '', 'process': 'kernel', 'pid': '',
        'message': log,
        'action': '', 'src_ip': '', 'dst_ip': '',
        'src_port': '', 'dst_port': '', 'proto': '',
        'in_iface': '', 'out_iface': '',
    }

    # Try to strip syslog wrapper
    m = _SYSLOG_WRAP.match(log)
    if m:
        result['timestamp'] = m.group('timestamp')
        result['hostname']  = m.group('hostname')
        chain   = m.group('chain')
        payload = m.group('kvpayload')

        # Detect UFW action from chain label
        ufwm = _UFW.search(chain)
        if ufwm:
            result['format'] = 'UFW'
            result['action'] = ufwm.group('action').upper()
        else:
            result['format'] = 'IPTABLES'
            result['action'] = 'DROP' if any(w in chain.upper()
                for w in ('DROP','REJECT','BLOCK','DENY')) else 'ACCEPT'

        kv = _parse_kv(payload)
        result.update({
            'in_iface':  kv.get('in', ''),
            'out_iface': kv.get('out', ''),
            'src_ip':    kv.get('src', ''),
            'dst_ip':    kv.get('dst', ''),
            'proto':     kv.get('proto', ''),
            'src_port':  kv.get('spt', ''),
            'dst_port':  kv.get('dpt', ''),
            'mac':       kv.get('mac', ''),
            'length':    kv.get('len', ''),
        })

        action  = result['action'] or 'RULE'
        src     = result['src_ip']  or '?'
        dst     = result['dst_ip']  or '?'
        proto   = result['proto']   or ''
        dpt     = result['dst_port'] or ''
        result['message'] = (
            f"{action} {proto} {src}:{result['src_port']} → {dst}:{dpt}"
            .replace(':','',1) if not result['src_port'] else
            f"{action} {proto} {src}:{result['src_port']} → {dst}:{dpt}"
        )
        return result

    # Raw kv payload without wrapper (e.g. forwarded stripped line)
    if 'SRC=' in log or 'src=' in log.lower():
        kv = _parse_kv(log)
        result['format']    = 'IPTABLES_RAW'
        result['src_ip']    = kv.get('src', '')
        result['dst_ip']    = kv.get('dst', '')
        result['proto']     = kv.get('proto', '')
        result['src_port']  = kv.get('spt', '')
        result['dst_port']  = kv.get('dpt', '')
        result['in_iface']  = kv.get('in', '')
        result['out_iface'] = kv.get('out', '')
        result['message']   = (
            f"FIREWALL {result['proto']} {result['src_ip']} → "
            f"{result['dst_ip']}:{result['dst_port']}"
        )
        return result

    return None  # Not a firewall log — let messagehandler use fallback
