import re

# =============================================================================
# parse_kernel.py — Linux Kernel / Audit Log Parser
#
# Formats handled:
#   1. Linux Audit daemon  (type=SYSCALL msg=audit(...) ...)
#   2. auditd EXECVE/PATH  (same audit envelope)
#   3. AppArmor denied     (apparmor="DENIED" operation=... profile=...)
#   4. SELinux AVC         (avc: denied { ... } for pid=...)
#   5. dmesg / kernel ring buffer  ([ uptime ] message)
#   6. OOM killer          (Out of memory: Kill process ...)
#   7. Kernel via syslog   (timestamp host kernel: message)
# =============================================================================

# ── 1 & 2. Linux Audit ───────────────────────────────────────────────────────
# type=SYSCALL msg=audit(1709778347.123:456): arch=c000003e syscall=59 ...
_AUDIT = re.compile(
    r'^type=(?P<audit_type>\S+)\s+'
    r'msg=audit\((?P<epoch>[\d.]+):(?P<serial>\d+)\):\s*'
    r'(?P<kvpayload>.+)$'
)

# ── 3. AppArmor ──────────────────────────────────────────────────────────────
_APPARMOR = re.compile(
    r'apparmor="(?P<verdict>[^"]+)".*?'
    r'operation="(?P<operation>[^"]+)".*?'
    r'profile="(?P<profile>[^"]+)".*?'
    r'name="(?P<name>[^"]*)"',
    re.IGNORECASE | re.DOTALL
)

# ── 4. SELinux AVC ───────────────────────────────────────────────────────────
_SELINUX = re.compile(
    r'avc:\s*(?P<verdict>denied|granted)\s*\{(?P<perms>[^}]+)\}\s*for\s+'
    r'pid=(?P<pid>\d+).*?'
    r'comm="(?P<comm>[^"]+)"',
    re.IGNORECASE | re.DOTALL
)

# ── 5. dmesg ─────────────────────────────────────────────────────────────────
_DMESG = re.compile(r'^\[\s*(?P<uptime>[\d.]+)\]\s+(?P<message>.+)$')

# ── 6. OOM killer ────────────────────────────────────────────────────────────
_OOM = re.compile(
    r'Out of memory:\s*Kill\s+(?:process|task)\s+(?P<pid>\d+)\s+'
    r'\((?P<comm>[^)]+)\)',
    re.IGNORECASE
)

# ── 7. Kernel syslog wrapper ─────────────────────────────────────────────────
_SYSLOG_KERNEL = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\S+|[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+kernel:\s*'
    r'(?:\[\s*[\d.]+\]\s*)?'
    r'(?P<body>.+)$'
)


def _parse_kv(payload: str) -> dict:
    result = {}
    for m in re.finditer(r'(\w+)=(?:"([^"]*)"|(\S+))', payload):
        result[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    return result


def parse_log(log: str) -> dict | None:
    if not log or not log.strip():
        return None

    log = log.strip()
    base = {
        'format': 'KERNEL', 'process': 'kernel', 'pid': '',
        'timestamp': '', 'hostname': '', 'message': log,
    }

    # Strip syslog wrapper first
    body = log
    m = _SYSLOG_KERNEL.match(log)
    if m:
        base['timestamp'] = m.group('timestamp')
        base['hostname']  = m.group('hostname')
        body = m.group('body')

    # 1. Linux Audit
    m = _AUDIT.match(body)
    if m:
        kv = _parse_kv(m.group('kvpayload'))
        audit_type = m.group('audit_type')
        base.update({
            'format':     'AUDIT_' + audit_type,
            'audit_type': audit_type,
            'epoch':      m.group('epoch'),
            'serial':     m.group('serial'),
            'pid':        kv.get('pid', ''),
            'uid':        kv.get('uid', ''),
            'auid':       kv.get('auid', ''),
            'comm':       kv.get('comm', '').strip('"'),
            'exe':        kv.get('exe', '').strip('"'),
            'syscall':    kv.get('syscall', ''),
            'success':    kv.get('success', ''),
            'kv':         kv,
        })
        comm = base['comm'] or kv.get('exe', '?')
        base['message'] = f"AUDIT {audit_type} pid={base['pid']} comm={comm}"
        return base

    # 3. AppArmor
    m = _APPARMOR.search(body)
    if m:
        base.update({
            'format':    'APPARMOR',
            'verdict':   m.group('verdict'),
            'operation': m.group('operation'),
            'profile':   m.group('profile'),
            'name':      m.group('name'),
        })
        base['message'] = (
            f"AppArmor {m.group('verdict').upper()} "
            f"op={m.group('operation')} profile={m.group('profile')} "
            f"name={m.group('name')}"
        )
        return base

    # 4. SELinux
    m = _SELINUX.search(body)
    if m:
        base.update({
            'format':  'SELINUX_AVC',
            'verdict': m.group('verdict'),
            'perms':   m.group('perms').strip(),
            'pid':     m.group('pid'),
            'comm':    m.group('comm'),
        })
        base['message'] = (
            f"SELinux AVC {m.group('verdict').upper()} "
            f"{{{m.group('perms').strip()}}} pid={m.group('pid')} "
            f"comm={m.group('comm')}"
        )
        return base

    # 6. OOM killer
    m = _OOM.search(body)
    if m:
        base.update({
            'format': 'OOM_KILLER',
            'pid':    m.group('pid'),
            'comm':   m.group('comm'),
        })
        base['message'] = f"OOM killer killed PID {m.group('pid')} ({m.group('comm')})"
        return base

    # 5. dmesg (only if body looks like dmesg)
    m = _DMESG.match(body)
    if m:
        base.update({
            'format':  'DMESG',
            'uptime':  m.group('uptime'),
            'message': m.group('message'),
        })
        return base

    # Generic kernel line (we got here from the syslog wrapper)
    if base['hostname']:  # wrapper was matched
        base['message'] = body
        return base

    return None   # not a kernel log
