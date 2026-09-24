import re

# =============================================================================
# parse_selinux.py — SELinux / Linux Audit Log Parser
#
# Source: /var/log/audit/audit.log  (auditd — RHEL, CentOS, Fedora, Rocky)
#         /var/log/kern.log         (kernel AVC messages on Debian/Ubuntu)
#
# Formats handled (in order):
#   1. AVC denial / grant     type=AVC  avc: denied { perms } for ...
#   2. SYSCALL record         type=SYSCALL  arch=... syscall=... exe=...
#   3. PATH record            type=PATH  item=... name=... inode=...
#   4. USER_AUTH / USER_LOGIN type=USER_* msg=audit(...) res=failed/success
#   5. PROCTITLE              type=PROCTITLE  proctitle=<hex or text>
#   6. Generic audit line     type=<ANY>  msg=audit(...): key=val ...
#   7. Kernel syslog AVC      (timestamp host kernel: avc: denied ...)
#   8. Fallback               anything that contains "avc:" or "audit("
#
# Return contract (same as all OpenSIEM modules):
#   dict with at minimum:
#       format    — identifies which branch matched
#       message   — human-readable summary (used for correlation matching)
#       timestamp — string (may be '' if not present)
#       hostname  — string ('' for raw auditd lines which have no hostname)
#       process   — string (comm or 'auditd')
#       pid       — string
#   Plus many audit-specific fields documented inline.
# =============================================================================


# ── Shared: auditd envelope ───────────────────────────────────────────────────
# type=AVC msg=audit(1709778347.123:456): ...
_AUDIT_HDR = re.compile(
    r'^type=(?P<audit_type>\S+)\s+'
    r'msg=audit\((?P<epoch>[\d.]+):(?P<serial>\d+)\):\s*'
    r'(?P<body>.+)$',
    re.DOTALL
)

# ── 1. AVC denial / grant ─────────────────────────────────────────────────────
# avc:  denied  { read write } for  pid=1234 comm="bash"
#       scontext=user_u:user_r:user_t:s0
#       tcontext=system_u:object_r:shadow_t:s0
#       tclass=file permissive=0
_AVC_BODY = re.compile(
    r'avc:\s*(?P<verdict>denied|granted)\s*'
    r'\{(?P<perms>[^}]+)\}\s+for\s+'
    r'(?P<kvpayload>.+)$',
    re.IGNORECASE | re.DOTALL
)

# ── 2. SYSCALL ────────────────────────────────────────────────────────────────
# arch=c000003e syscall=59 success=yes exit=0 a0=... pid=1234 uid=0 ...
# comm="bash" exe="/bin/bash" subj=... key=(null)
_SYSCALL = re.compile(
    r'arch=\S+\s+syscall=(?P<syscall>\d+)\s+success=(?P<success>\S+)'
    r'.*?pid=(?P<pid>\d+).*?uid=(?P<uid>\d+).*?'
    r'comm="(?P<comm>[^"]*)".*?exe="(?P<exe>[^"]*)"',
    re.DOTALL
)

# ── 3. PATH ───────────────────────────────────────────────────────────────────
# item=0 name="/etc/shadow" inode=12345 dev=fd:00 mode=0100640 ...
_PATH_BODY = re.compile(
    r'item=(?P<item>\d+).*?name="(?P<name>[^"]*)"',
    re.DOTALL
)

# ── 4. USER_* events ─────────────────────────────────────────────────────────
# pid=1234 uid=0 auid=4294967295 ses=4294967295 subj=... msg='op=PAM:... acct="root" exe="/usr/sbin/sshd" hostname=... addr=... terminal=ssh res=failed'
_USER_EVT = re.compile(
    r"pid=(?P<pid>\d+).*?uid=(?P<uid>\d+).*?msg='(?P<inner>[^']*)'",
    re.DOTALL
)
_USER_INNER = re.compile(
    r'(?:acct|id)="(?P<acct>[^"]*)".*?exe="(?P<exe>[^"]*)"'
    r'.*?(?:hostname=(?P<hostname>\S+))?.*?(?:addr=(?P<addr>\S+))?'
    r'.*?res=(?P<res>\S+)',
    re.DOTALL
)

# ── 5. PROCTITLE ─────────────────────────────────────────────────────────────
_PROCTITLE = re.compile(r'proctitle=(?P<raw>.+)$')

# ── 7. Kernel syslog wrapper ─────────────────────────────────────────────────
_KERN_WRAP = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\S+|[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
    r'\s+(?P<hostname>\S+)\s+kernel:\s*'
    r'(?:\[\s*[\d.]+\]\s*)?'
    r'(?P<body>.+)$'
)


# =============================================================================
# Helpers
# =============================================================================

def _parse_kv(text: str) -> dict:
    """Extract key=value and key="value" pairs from an audit body."""
    result = {}
    for m in re.finditer(r'(\w+)=(?:"([^"]*)"|(\S+))', text):
        key = m.group(1)
        val = m.group(2) if m.group(2) is not None else m.group(3)
        result[key] = val
    return result


def _decode_proctitle(raw: str) -> str:
    """
    PROCTITLE is either a quoted string or a hex dump where args are
    separated by 00 bytes.  Return a readable string in both cases.
    """
    raw = raw.strip()
    # Hex dump: all hex chars, even length
    if re.fullmatch(r'[0-9A-Fa-f]+', raw) and len(raw) % 2 == 0:
        try:
            decoded = bytes.fromhex(raw).decode('utf-8', errors='replace')
            # Replace null bytes (arg separators) with spaces
            return decoded.replace('\x00', ' ').strip()
        except Exception:
            pass
    return raw.strip('"')


def _context_role(ctx: str) -> str:
    """Extract the SELinux type from a context string like user_u:role_r:type_t:s0."""
    parts = ctx.split(':')
    return parts[2] if len(parts) >= 3 else ctx


# =============================================================================
# Main parser
# =============================================================================

def parse_log(log: str) -> dict | None:
    if not log or not log.strip():
        return None

    log = log.strip()

    base = {
        'format':    'SELINUX',
        'timestamp': '',
        'hostname':  '',
        'process':   'auditd',
        'pid':       '',
        'message':   log,
    }

    # ── 7. Strip kernel syslog wrapper if present ─────────────────────────────
    body = log
    m = _KERN_WRAP.match(log)
    if m:
        base['timestamp'] = m.group('timestamp')
        base['hostname']  = m.group('hostname')
        body = m.group('body')

    # ── Parse auditd envelope ─────────────────────────────────────────────────
    mh = _AUDIT_HDR.match(body)
    if not mh:
        # ── 8. Fallback: bare avc: line without envelope ───────────────────────
        if 'avc:' in body.lower() or 'audit(' in body:
            base['format']  = 'SELINUX_RAW'
            base['message'] = body
            return base
        return None   # not a SELinux / audit log

    audit_type = mh.group('audit_type')
    epoch      = mh.group('epoch')
    serial     = mh.group('serial')
    evt_body   = mh.group('body')

    base.update({
        'audit_type': audit_type,
        'epoch':      epoch,
        'serial':     serial,
    })

    # ── 1. AVC ────────────────────────────────────────────────────────────────
    if audit_type == 'AVC':
        ma = _AVC_BODY.search(evt_body)
        if ma:
            kv      = _parse_kv(ma.group('kvpayload'))
            verdict = ma.group('verdict').upper()
            perms   = ma.group('perms').strip()
            comm    = kv.get('comm', '').strip('"')
            exe     = kv.get('exe', '').strip('"')
            path    = kv.get('path', '').strip('"') or kv.get('name', '').strip('"')
            sctx    = kv.get('scontext', '')
            tctx    = kv.get('tcontext', '')
            tclass  = kv.get('tclass', '')
            permissive = kv.get('permissive', '0')

            base.update({
                'format':      'SELINUX_AVC',
                'verdict':     verdict,
                'permissions': perms,
                'pid':         kv.get('pid', ''),
                'comm':        comm,
                'exe':         exe,
                'path':        path,
                'scontext':    sctx,
                'tcontext':    tctx,
                'tclass':      tclass,
                'permissive':  permissive == '1',
                'stype':       _context_role(sctx),
                'ttype':       _context_role(tctx),
                'kv':          kv,
            })

            perm_flag = ' [PERMISSIVE]' if permissive == '1' else ''
            base['message'] = (
                f"SELinux AVC {verdict}{perm_flag}: "
                f"{{{perms}}} on {tclass} "
                f"stype={_context_role(sctx)} ttype={_context_role(tctx)} "
                f"comm={comm or exe or '?'} path={path}"
            )
            return base

    # ── 2. SYSCALL ────────────────────────────────────────────────────────────
    if audit_type == 'SYSCALL':
        ms = _SYSCALL.search(evt_body)
        kv = _parse_kv(evt_body)
        if ms:
            base.update({
                'format':  'SELINUX_SYSCALL',
                'syscall': ms.group('syscall'),
                'success': ms.group('success'),
                'pid':     ms.group('pid'),
                'uid':     ms.group('uid'),
                'comm':    ms.group('comm'),
                'exe':     ms.group('exe'),
                'key':     kv.get('key', '').strip('"'),
                'subj':    kv.get('subj', ''),
                'kv':      kv,
            })
            base['message'] = (
                f"Audit SYSCALL {ms.group('syscall')} "
                f"success={ms.group('success')} "
                f"pid={ms.group('pid')} uid={ms.group('uid')} "
                f"comm={ms.group('comm')} exe={ms.group('exe')}"
            )
        else:
            # Generic SYSCALL fallback
            kv = _parse_kv(evt_body)
            base.update({'format': 'SELINUX_SYSCALL', 'kv': kv,
                         'pid': kv.get('pid', ''), 'comm': kv.get('comm', '')})
            base['message'] = f"Audit SYSCALL pid={kv.get('pid','')} comm={kv.get('comm','')}"
        return base

    # ── 3. PATH ───────────────────────────────────────────────────────────────
    if audit_type == 'PATH':
        mp = _PATH_BODY.search(evt_body)
        kv = _parse_kv(evt_body)
        name = mp.group('name') if mp else kv.get('name', '')
        base.update({
            'format': 'SELINUX_PATH',
            'path':   name,
            'mode':   kv.get('mode', ''),
            'ouid':   kv.get('ouid', ''),
            'ogid':   kv.get('ogid', ''),
            'kv':     kv,
        })
        base['message'] = f"Audit PATH name={name} mode={kv.get('mode','')} ouid={kv.get('ouid','')}"
        return base

    # ── 4. USER_* events (AUTH, LOGIN, CMD, ACCT, etc.) ──────────────────────
    if audit_type.startswith('USER_') or audit_type in ('CRED_ACQ', 'CRED_DISP',
                                                          'LOGIN', 'LOGOUT',
                                                          'ADD_USER', 'DEL_USER'):
        mu = _USER_EVT.search(evt_body)
        kv = _parse_kv(evt_body)
        res = 'unknown'
        acct = ''
        exe  = ''
        addr = ''
        hn   = ''

        if mu:
            inner = mu.group('inner')
            mi = _USER_INNER.search(inner)
            if mi:
                acct = mi.group('acct') or ''
                exe  = mi.group('exe')  or ''
                res  = (mi.group('res') or 'unknown').strip("'")
                addr = mi.group('addr') or kv.get('addr', '')
                hn   = mi.group('hostname') or kv.get('hostname', '')
                if hn and not base['hostname']:
                    base['hostname'] = hn
            else:
                res  = kv.get('res', 'unknown').strip("'")
                acct = kv.get('acct', '').strip('"')

        base.update({
            'format':     f'SELINUX_{audit_type}',
            'pid':        mu.group('pid') if mu else kv.get('pid', ''),
            'uid':        mu.group('uid') if mu else kv.get('uid', ''),
            'acct':       acct,
            'exe':        exe,
            'result':     res,
            'src_ip':     addr,
            'kv':         kv,
        })
        status = 'SUCCESS' if res.lower() in ('success', 'yes') else 'FAILURE'
        base['message'] = (
            f"Audit {audit_type} {status}: "
            f"acct={acct} exe={exe} src={addr}"
        )
        return base

    # ── 5. PROCTITLE ─────────────────────────────────────────────────────────
    if audit_type == 'PROCTITLE':
        mp = _PROCTITLE.search(evt_body)
        if mp:
            decoded = _decode_proctitle(mp.group('raw'))
            base.update({
                'format':    'SELINUX_PROCTITLE',
                'proctitle': decoded,
                'message':   f"Audit PROCTITLE: {decoded[:120]}",
            })
        return base

    # ── 6. Generic audit line ─────────────────────────────────────────────────
    kv = _parse_kv(evt_body)
    base.update({
        'format': f'SELINUX_{audit_type}',
        'kv':     kv,
        'pid':    kv.get('pid', ''),
    })
    base['message'] = f"Audit {audit_type}: {evt_body[:120]}"
    return base
