import re

# =============================================================================
# parse_ssh.py — OpenSSH / SSHD Log Parser
#
# Source: /var/log/auth.log or /var/log/secure (sshd entries)
# Note:   parse_auth.py handles the full auth.log file including PAM, sudo,
#         su, etc. This module specialises in sshd-only lines and extracts
#         richer fields (key fingerprint, session duration, subsystem...).
#         The watcher.conf should point one source at the auth log using
#         parse_auth and a separate source at the sshd dedicated log (if any)
#         using parse_ssh. Or use only parse_auth — both are valid.
#
# Formats handled:
#   1. Accepted / Failed authentication
#   2. Connection closed / disconnected
#   3. Invalid / illegal user
#   4. Too many authentication failures
#   5. Subsystem request (sftp etc.)
#   6. Key fingerprint lines
#   7. PAM / session open/close (sshd-specific)
# =============================================================================

_SYSLOG = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\S+|[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+'
    r'(?P<body>.+)$'
)

# ── Auth result ────────────────────────────────────────────────────────────────
_ACCEPTED = re.compile(
    r'^Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+'
    r'(?P<src_ip>[\d.:a-fA-F]+)\s+port\s+(?P<src_port>\d+)',
    re.IGNORECASE
)
_FAILED = re.compile(
    r'^Failed\s+(?P<method>\S+)\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+'
    r'(?P<src_ip>[\d.:a-fA-F]+)\s+port\s+(?P<src_port>\d+)',
    re.IGNORECASE
)
_INVALID = re.compile(
    r'^Invalid user\s+(?P<user>\S+)\s+from\s+(?P<src_ip>[\d.:a-fA-F]+)'
    r'\s+port\s+(?P<src_port>\d+)',
    re.IGNORECASE
)
_TOO_MANY = re.compile(
    r'^Disconnecting\s+(?:invalid user\s+)?(?P<user>\S+)\s+'
    r'(?P<src_ip>[\d.:a-fA-F]+)\s+port\s+(?P<src_port>\d+).*'
    r'Too many authentication failures',
    re.IGNORECASE
)

# ── Connection lifecycle ───────────────────────────────────────────────────────
_CONNECT = re.compile(
    r'^Connection from\s+(?P<src_ip>[\d.:a-fA-F]+)\s+port\s+(?P<src_port>\d+)',
    re.IGNORECASE
)
_DISCONNECT = re.compile(
    r'^(?:Disconnected from|Connection closed by)\s+(?:(?:invalid user|authenticating user)\s+)?'
    r'(?:(?P<user>\S+)\s+)?(?P<src_ip>[\d.:a-fA-F]+)\s+port\s+(?P<src_port>\d+)',
    re.IGNORECASE
)

# ── Subsystem / key ───────────────────────────────────────────────────────────
_SUBSYSTEM = re.compile(
    r'^subsystem request for\s+(?P<subsystem>\S+)',
    re.IGNORECASE
)
_FINGERPRINT = re.compile(
    r'key fingerprint\s+(?:is\s+)?(?P<fingerprint>\S+)',
    re.IGNORECASE
)


def parse_log(log: str) -> dict | None:
    if not log or not log.strip():
        return None

    log = log.strip()

    # Must come from sshd
    m = _SYSLOG.match(log)
    if not m:
        # bare body line (syslog wrapper already stripped upstream)
        body = log
        base = {'timestamp': '', 'hostname': '', 'pid': '', 'process': 'sshd'}
    else:
        body = m.group('body')
        base = {
            'timestamp': m.group('timestamp'),
            'hostname':  m.group('hostname'),
            'pid':       m.group('pid'),
            'process':   'sshd',
        }

    result = {**base, 'format': 'SSH', 'message': body,
              'user': '', 'src_ip': '', 'src_port': '', 'method': '',
              'action': '', 'subsystem': '', 'fingerprint': ''}

    # 1. Accepted
    m = _ACCEPTED.match(body)
    if m:
        result.update(m.groupdict())
        result['action']  = 'ACCEPTED'
        result['format']  = 'SSH_ACCEPTED'
        result['message'] = (
            f"SSH login accepted: user={m.group('user')} method={m.group('method')} "
            f"from={m.group('src_ip')}:{m.group('src_port')}"
        )
        return result

    # 2. Failed
    m = _FAILED.match(body)
    if m:
        result.update(m.groupdict())
        result['action']  = 'FAILED'
        result['format']  = 'SSH_FAILED'
        result['message'] = (
            f"SSH login failed: user={m.group('user')} method={m.group('method')} "
            f"from={m.group('src_ip')}:{m.group('src_port')}"
        )
        return result

    # 3. Invalid user
    m = _INVALID.match(body)
    if m:
        result.update(m.groupdict())
        result['action']  = 'INVALID_USER'
        result['format']  = 'SSH_INVALID_USER'
        result['message'] = (
            f"SSH invalid user: user={m.group('user')} "
            f"from={m.group('src_ip')}:{m.group('src_port')}"
        )
        return result

    # 4. Too many auth failures
    m = _TOO_MANY.match(body)
    if m:
        result.update({k: v for k, v in m.groupdict().items() if v})
        result['action']  = 'BRUTE_FORCE'
        result['format']  = 'SSH_BRUTE_FORCE'
        result['message'] = (
            f"SSH brute force: user={result['user']} "
            f"from={result['src_ip']}:{result['src_port']}"
        )
        return result

    # 5. Connection / disconnect
    m = _DISCONNECT.match(body)
    if m:
        result.update({k: v for k, v in m.groupdict().items() if v})
        result['action']  = 'DISCONNECTED'
        result['format']  = 'SSH_DISCONNECT'
        result['message'] = (
            f"SSH disconnected: {result.get('user','')} "
            f"from={result['src_ip']}:{result['src_port']}"
        )
        return result

    m = _CONNECT.match(body)
    if m:
        result.update(m.groupdict())
        result['action']  = 'CONNECT'
        result['format']  = 'SSH_CONNECT'
        result['message'] = (
            f"SSH connection: from={m.group('src_ip')}:{m.group('src_port')}"
        )
        return result

    # 6. Subsystem
    m = _SUBSYSTEM.match(body)
    if m:
        result['subsystem'] = m.group('subsystem')
        result['action']    = 'SUBSYSTEM'
        result['format']    = 'SSH_SUBSYSTEM'
        result['message']   = f"SSH subsystem: {m.group('subsystem')}"
        return result

    # If it came through sshd wrapper but didn't match a pattern, still return it
    if base.get('hostname'):
        result['message'] = body
        return result

    return None
