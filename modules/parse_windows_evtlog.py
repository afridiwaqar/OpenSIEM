import re

# =============================================================================
# parse_windows_evtlog.py — Windows Event Log Parser
#
# Parses log lines produced by watcher_windows.py and forwarded to OpenSIEM
# over TCP in the standard wire format:
#
#   {source_ip} modules/parse_windows_evtlog.py {log_line}
#
# The log line format produced by the watcher is:
#   WinEvt channel=Security event_id=4624 record=12345 time=2026-01-01T09:00:00
#          source='Microsoft-Windows-Security-Auditing' user='DOMAIN\\alice'
#          computer='WORKSTATION01' msg='An account was successfully logged on ...'
# =============================================================================

_LINE = re.compile(
    r"^WinEvt\s+"
    r"channel=(\S+)\s+"
    r"event_id=(\d+)\s+"
    r"record=(\d+)\s+"
    r"time=(\S+)\s+"
    r"source='([^']*)'\s+"
    r"user='([^']*)'\s+"
    r"computer='([^']*)'\s+"
    r"msg='(.*)'$",
    re.DOTALL
)

# Maps Event IDs to a human-readable action name.
# Administrators: add new mappings here as needed.
_ACTION_MAP = {
    # Logon / Logoff
    4624: "LOGIN_SUCCESS",
    4625: "LOGIN_FAILED",
    4634: "LOGOFF",
    4647: "LOGOFF",
    4648: "RUNAS_LOGON",
    4672: "PRIVILEGED_LOGON",
    # Process
    4688: "PROCESS_CREATE",
    4689: "PROCESS_EXIT",
    # Scheduled tasks
    4698: "TASK_CREATED",
    4699: "TASK_DELETED",
    4700: "TASK_ENABLED",
    4701: "TASK_DISABLED",
    # Account management
    4720: "ACCOUNT_CREATED",
    4722: "ACCOUNT_ENABLED",
    4723: "PASSWORD_CHANGE_ATTEMPT",
    4724: "PASSWORD_RESET",
    4725: "ACCOUNT_DISABLED",
    4726: "ACCOUNT_DELETED",
    4728: "GROUP_MEMBER_ADDED",
    4732: "GROUP_MEMBER_ADDED",
    4738: "ACCOUNT_CHANGED",
    4740: "ACCOUNT_LOCKED",
    4756: "GROUP_MEMBER_ADDED",
    # Kerberos / NTLM
    4768: "KERBEROS_TGT_REQUEST",
    4769: "KERBEROS_SERVICE_TICKET",
    4771: "KERBEROS_PRE_AUTH_FAILED",
    4776: "NTLM_AUTH_ATTEMPT",
    # Enumeration
    4798: "LOCAL_GROUP_ENUM",
    4799: "LOCAL_GROUP_ENUM",
    # Network shares
    5140: "SHARE_ACCESSED",
    5145: "SHARE_ACCESS_CHECK",
    # Services
    7034: "SERVICE_CRASHED",
    7036: "SERVICE_STATE_CHANGED",
    7040: "SERVICE_CONFIG_CHANGED",
    7045: "SERVICE_INSTALLED",
    # Shutdown / startup
    1074: "SYSTEM_SHUTDOWN",
    6005: "SYSTEM_STARTUP",
    6006: "SYSTEM_SHUTDOWN",
    6008: "UNEXPECTED_SHUTDOWN",
    # Application
    1000: "APPLICATION_CRASH",
    1001: "APPLICATION_CRASH_REPORT",
    1002: "APPLICATION_HANG",
}

# Event IDs that represent failed or suspicious actions — mapped to mid/high severity.
_HIGH_SEVERITY = {4625, 4740, 4771, 4776}
_MID_SEVERITY  = {4648, 4672, 4698, 4699, 4720, 4726, 4728, 4732,
                  4738, 4756, 7045, 6008, 1000}


def _map_severity(event_id: int, channel: str) -> str:
    if event_id in _HIGH_SEVERITY:
        return "high"
    if event_id in _MID_SEVERITY:
        return "mid"
    if channel.lower() == "security":
        return "mid"
    return "low"


def parse_log(log: str) -> dict | None:
    if not log or not log.strip():
        return None

    log = log.strip()

    if not log.startswith("WinEvt "):
        return None

    m = _LINE.match(log)
    if not m:
        return None

    channel, event_id_s, record_s, timestamp, source, user, computer, msg = m.groups()

    try:
        event_id = int(event_id_s)
    except ValueError:
        return None

    action   = _ACTION_MAP.get(event_id, f"EVENT_{event_id}")
    severity = _map_severity(event_id, channel)

    return {
        "format":       "WINDOWS_EVTLOG",
        "timestamp":    timestamp,
        "hostname":     computer,
        "process":      source,
        "pid":          record_s,
        "level":        severity,
        "channel":      channel,
        "event_id":     event_id,
        "action":       action,
        "user":         user,
        "computer":     computer,
        "source":       source,
        "message":      f"Windows {action} [{channel}:{event_id}] user={user} {msg[:300]}",
        "raw_message":  msg,
    }
