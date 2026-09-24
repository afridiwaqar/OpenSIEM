import re

# =============================================================================
# parse_cron.py — Cron / Anacron / At Log Parser
#
# Source: /var/log/syslog (cron entries) or /var/log/cron.log
#
# Formats handled:
#   1. crond / cron job execution
#   2. PAM session open/close for cron
#   3. anacron messages
#   4. at / atd job execution
# =============================================================================

_SYSLOG = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\S+|[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+'
    r'(?P<daemon>cron(?:d)?|anacron|atd|CRON|AT)\[(?P<pid>\d+)\]:\s+'
    r'(?P<body>.+)$',
    re.IGNORECASE
)

# CRON[pid]: (user) CMD (command)
_CRON_CMD = re.compile(
    r'^\((?P<user>[^)]+)\)\s+CMD\s+\((?P<command>.+)\)$',
    re.IGNORECASE
)

# CRON[pid]: (user) MAIL (mailed 0 bytes of output; but got status 0)
_CRON_MAIL = re.compile(
    r'^\((?P<user>[^)]+)\)\s+MAIL\s+\((?P<detail>.+)\)$',
    re.IGNORECASE
)

# PAM session
_PAM_SESSION = re.compile(
    r'^pam_unix\(cron:session\):\s+session\s+(?P<state>opened|closed)\s+'
    r'for user\s+(?P<user>\S+)',
    re.IGNORECASE
)

# anacron
_ANACRON = re.compile(
    r'^(?:Job\s+`(?P<job>[^\']+)\'\s+(?P<action>started|terminated)|'
    r'(?P<msg>.+))$',
    re.IGNORECASE
)


def parse_log(log: str) -> dict | None:
    if not log or not log.strip():
        return None

    log = log.strip()

    m = _SYSLOG.match(log)
    if not m:
        return None

    base = {
        'format':    'CRON',
        'timestamp': m.group('timestamp'),
        'hostname':  m.group('hostname'),
        'process':   m.group('daemon').lower(),
        'pid':       m.group('pid'),
        'user':      '',
        'command':   '',
        'action':    '',
        'message':   m.group('body'),
    }
    body = m.group('body')

    # CMD
    mc = _CRON_CMD.match(body)
    if mc:
        base.update({
            'action':  'JOB_EXEC',
            'user':    mc.group('user'),
            'command': mc.group('command'),
            'message': f"Cron job: user={mc.group('user')} cmd={mc.group('command')[:120]}",
        })
        return base

    # MAIL
    mc = _CRON_MAIL.match(body)
    if mc:
        base.update({
            'action':  'JOB_MAIL',
            'user':    mc.group('user'),
            'message': f"Cron mail: user={mc.group('user')} {mc.group('detail')}",
        })
        return base

    # PAM session
    mc = _PAM_SESSION.match(body)
    if mc:
        base.update({
            'action':  'SESSION_' + mc.group('state').upper(),
            'user':    mc.group('user'),
            'message': f"Cron session {mc.group('state')}: user={mc.group('user')}",
        })
        return base

    # anacron
    if base['process'] == 'anacron':
        mc = _ANACRON.match(body)
        if mc and mc.group('job'):
            base.update({
                'action':  mc.group('action', '').upper() if mc.lastgroup else '',
                'message': f"Anacron job {mc.group('job')}: {mc.group('action','')}",
            })
        return base

    return base
