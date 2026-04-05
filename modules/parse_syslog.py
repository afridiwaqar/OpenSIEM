import re

# =============================================================================
# parse_syslog.py  —  Comprehensive Syslog Parser
#
# Formats handled (tried in order):
#   1.  RFC 5424          Full structured syslog  <PRI>VERSION TIMESTAMP HOST APP PID MSGID SD MSG
#   2.  RFC 5424 No-SD    RFC 5424 without structured data field
#   3.  RFC 5424 PRI-only <PRI> stripped prefix before an otherwise RFC3164 line
#   4.  RFC 3164          Classic BSD  <PRI>Mon DD HH:MM:SS host proc[pid]: msg
#   5.  RFC 3164 No-PRI   Mon DD HH:MM:SS host proc[pid]: msg  (PRI stripped by relay)
#   6.  ISO 8601          Modern Linux  YYYY-MM-DDTHH:MM:SS±TZ host proc[pid]: msg
#   7.  ISO 8601 UTC Z    Same but with trailing 'Z'  e.g. 2026-03-07T01:25:47Z
#   8.  ISO 8601 No-TZ    Timestamp without timezone  2026-03-07T01:25:47.123456
#   9.  RSYSLOG TraditionalFormat  Mon DD HH:MM:SS host proc[pid]: msg  (same as RFC3164 No-PRI)
#  10.  Syslog-ng default Mon DD HH:MM:SS host proc[pid]: msg  (same base, kept separate label)
#  11.  Journald export   Journald text output with _SYSTEMD fields stripped to core fields
#  12.  Cisco IOS         *MM DD YYYY: HH:MM:SS.mmm TIMEZONE: %FACILITY-SEV-MNEMONIC: msg
#  13.  Cisco ASA/FTD     timestamp host : %ASA-SEV-CODE: msg
#  14.  Juniper Junos     timestamp hostname PROCESS[PID]: msg  (ISO or BSD timestamp)
#  15.  Windows Event Log Forwarded  MM/DD/YYYY HH:MM:SS host EventID Source msg
#  16.  CEF (ArcSight)    CEF:Version|Device|Product|Version|SignatureID|Name|Severity|Extension
#  17.  LEEF (IBM QRadar) LEEF:Version|Vendor|Product|Version|EventID|key=val...
#  18.  WELF (WebTrends)  id=firewall time="..." fw=... msg=...
#  19.  Syslog with year  YYYY Mon DD HH:MM:SS host proc[pid]: msg
#  20.  No-host shortform proc[pid]: msg  (local syslog without hostname)
#  21.  Kernel (dmesg)    [ seconds.usec ] message  OR  kernel: message
#  22.  Fallback          Anything remaining — best-effort extraction
# =============================================================================


# ── 1. RFC 5424 ──────────────────────────────────────────────────────────────
# <34>1 2026-03-07T01:25:47.123456+05:00 myhostname myapp 1234 ID47 [exampleSDID@32473 iut="3"] message
RFC5424 = re.compile(
    r'^<(?P<pri>\d{1,3})>(?P<version>\d+)\s+'
    r'(?P<timestamp>\S+)\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<appname>\S+)\s+'
    r'(?P<pid>\S+)\s+'
    r'(?P<msgid>\S+)\s+'
    r'(?P<structured_data>-|\[.*?\](?:\[.*?\])*)\s*'
    r'(?P<message>.*)$',
    re.DOTALL
)

# ── 2. RFC 5424 No Structured Data ───────────────────────────────────────────
# Some implementations omit structured data entirely
RFC5424_NOSD = re.compile(
    r'^<(?P<pri>\d{1,3})>(?P<version>\d+)\s+'
    r'(?P<timestamp>\S+)\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<appname>\S+)\s+'
    r'(?P<pid>\S+)\s+'
    r'(?P<msgid>\S+)\s+'
    r'(?P<message>.*)$'
)

# ── 3. RFC 5424 PRI + RFC 3164 body ──────────────────────────────────────────
# <34>Mar  7 01:25:47 hostname process[pid]: message
RFC5424_PRI_3164 = re.compile(
    r'^<(?P<pri>\d{1,3})>'
    r'(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<process>[^\[\s:]+)(?:\[(?P<pid>\d+)\])?:?\s*'
    r'(?P<message>.*)$'
)

# ── 4. RFC 3164 with PRI ──────────────────────────────────────────────────────
# <34>Mar  7 01:25:47 hostname process[pid]: message
RFC3164_PRI = re.compile(
    r'^<(?P<pri>\d{1,3})>'
    r'(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<process>[^\[\s:]+)(?:\[(?P<pid>\d+)\])?:?\s*'
    r'(?P<message>.*)$'
)

# ── 5. RFC 3164 No PRI ───────────────────────────────────────────────────────
# Mar  7 01:25:47 hostname process[pid]: message
RFC3164 = re.compile(
    r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<process>[^\[\s:]+)(?:\[(?P<pid>\d+)\])?:?\s*'
    r'(?P<message>.*)$'
)

# ── 6. ISO 8601 with timezone offset ─────────────────────────────────────────
# 2026-03-07T01:25:47.123456+05:00 hostname process[pid]: message
ISO8601 = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<process>[^\[\s:]+)(?:\[(?P<pid>\d+)\])?:?\s*'
    r'(?P<message>.*)$'
)

# ── 7. ISO 8601 UTC (Z suffix) ───────────────────────────────────────────────
# 2026-03-07T01:25:47.123456Z hostname process[pid]: message
ISO8601_UTC = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<process>[^\[\s:]+)(?:\[(?P<pid>\d+)\])?:?\s*'
    r'(?P<message>.*)$'
)

# ── 8. ISO 8601 No timezone ──────────────────────────────────────────────────
# 2026-03-07T01:25:47.123456 hostname process[pid]: message
ISO8601_NOTZ = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<process>[^\[\s:]+)(?:\[(?P<pid>\d+)\])?:?\s*'
    r'(?P<message>.*)$'
)

# ── 9. Syslog with 4-digit year prepended ────────────────────────────────────
# 2026 Mar  7 01:25:47 hostname process[pid]: message
SYSLOG_WITH_YEAR = re.compile(
    r'^(?P<year>\d{4})\s+'
    r'(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<process>[^\[\s:]+)(?:\[(?P<pid>\d+)\])?:?\s*'
    r'(?P<message>.*)$'
)

# ── 10. Cisco IOS Syslog ──────────────────────────────────────────────────────
# *Mar  7 2026: 01:25:47.123 UTC: %SYS-5-CONFIG_I: Configured from console
# Also: 000123: Mar  7 01:25:47.123: %LINK-3-UPDOWN: ...
CISCO_IOS = re.compile(
    r'^(?:\*|\.)?(?:\d+:\s*)?'
    r'(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}(?:\s+\d{4})?\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)'
    r'(?:\s+(?P<timezone>[A-Z]{2,5}))?:\s*'
    r'%(?P<facility>[A-Z0-9_-]+)-(?P<severity>\d)-(?P<mnemonic>[A-Z0-9_]+):\s*'
    r'(?P<message>.*)$'
)

# ── 11. Cisco ASA / FTD ───────────────────────────────────────────────────────
# Mar 07 2026 01:25:47 ASA-FW : %ASA-6-302013: Built inbound TCP connection
CISCO_ASA = re.compile(
    r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s*:\s*'
    r'%ASA-(?P<severity>\d)-(?P<msgid>\d+):\s*'
    r'(?P<message>.*)$'
)

# ── 12. Windows Event Log (forwarded via WEF/NXLog/Winlogbeat) ───────────────
# 03/07/2026 01:25:47 WIN-HOST EventID=4624 Source=Security message text
WINDOWS_EVT = re.compile(
    r'^(?P<timestamp>\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+'
    r'EventID=(?P<event_id>\d+)\s+'
    r'Source=(?P<source>\S+)\s+'
    r'(?P<message>.*)$'
)

# ── 13. CEF — Common Event Format (ArcSight) ─────────────────────────────────
# CEF:0|Vendor|Product|1.0|100|Login Failure|5|src=1.2.3.4 dst=5.6.7.8
CEF = re.compile(
    r'^CEF:(?P<cef_version>\d+)\|'
    r'(?P<device_vendor>[^|]*)\|'
    r'(?P<device_product>[^|]*)\|'
    r'(?P<device_version>[^|]*)\|'
    r'(?P<signature_id>[^|]*)\|'
    r'(?P<name>[^|]*)\|'
    r'(?P<severity>[^|]*)\|'
    r'(?P<extension>.*)$'
)

# ── 14. LEEF — Log Event Extended Format (IBM QRadar) ────────────────────────
# LEEF:2.0|Vendor|Product|1.0|EventID|key=val\tkey=val
LEEF = re.compile(
    r'^LEEF:(?P<leef_version>[^|]+)\|'
    r'(?P<vendor>[^|]*)\|'
    r'(?P<product>[^|]*)\|'
    r'(?P<version>[^|]*)\|'
    r'(?P<event_id>[^|]*)\|'
    r'(?P<attributes>.*)$'
)

# ── 15. WELF — WebTrends Enhanced Log Format ─────────────────────────────────
# id=firewall time="2026-03-07 01:25:47" fw="hostname" msg="something happened"
WELF = re.compile(
    r'^id=(?P<device_id>\S+)\s+'
    r'time="(?P<timestamp>[^"]+)"\s+'
    r'fw="(?P<hostname>[^"]+)"\s+'
    r'(?P<attributes>.*?)\s*'
    r'msg="(?P<message>[^"]*)"',
    re.IGNORECASE
)

# ── 16. Kernel / dmesg ───────────────────────────────────────────────────────
# [12345.678901] usb 1-1: new high-speed USB device number 2 using xhci_hcd
# OR: kernel: usb 1-1: new high-speed USB device
DMESG = re.compile(
    r'^\[\s*(?P<uptime>\d+\.\d+)\]\s+(?P<message>.*)$'
)

KERNEL_SYSLOG = re.compile(
    r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+kernel:\s+'
    r'(?P<message>.*)$'
)

# ── 17. Journald text export ──────────────────────────────────────────────────
# Journald with SYSLOG_IDENTIFIER, _PID, __REALTIME_TIMESTAMP in key=value pairs.
# Simplified: capture the MESSAGE= line which is what matters.
JOURNALD = re.compile(
    r'(?:^|\s)MESSAGE=(?P<message>.+?)(?:\s+[A-Z_]+=|$)',
    re.MULTILINE
)

# ── 18. Juniper Junos ─────────────────────────────────────────────────────────
# Same structure as RFC3164 but often with ISO timestamp
# 2026-03-07T01:25:47+05:00 router-fw mgd[1234]: UI_COMMIT: message
JUNOS = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2})?)\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<process>[^\[\s:]+)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<mnemonic>[A-Z0-9_]+):\s+'
    r'(?P<message>.*)$'
)

# ── 19. No-host shortform (local syslog, hostname stripped) ──────────────────
# Mar  7 01:25:47 process[pid]: message
# pid brackets REQUIRED to distinguish from RFC3164 (where 3rd token = hostname)
NO_HOST_RFC3164 = re.compile(
    r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<process>[^\[\s:]+)\[(?P<pid>\d+)\]:\s+'
    r'(?P<message>.*)$'
)

# ── 20. Process-only (no timestamp, no host) ─────────────────────────────────
# process[pid]: message
# process: message
PROCESS_ONLY = re.compile(
    r'^(?P<process>[A-Za-z0-9._/-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)$'
)

# ── 21. Fallback ─────────────────────────────────────────────────────────────
FALLBACK = re.compile(
    r'^(?P<process>[A-Za-z0-9._-]+)(?:\[(?P<pid>\d+)\])?:?\s*(?P<message>.*)$'
)


# =============================================================================
# Helpers
# =============================================================================

def _clean(d):
    """Return groupdict with None values replaced by empty string."""
    return {k: (v if v is not None else '') for k, v in d.items()}


def _parse_leef_attributes(attr_str):
    """Split LEEF key=val pairs (tab or space delimited)."""
    pairs = {}
    for part in re.split(r'[\t ]', attr_str):
        if '=' in part:
            k, _, v = part.partition('=')
            pairs[k] = v
    return pairs


def _parse_cef_extension(ext_str):
    """Split CEF extension key=val pairs."""
    pairs = {}
    for m in re.finditer(r'(\w+)=((?:(?!\w+=).)*)', ext_str):
        pairs[m.group(1)] = m.group(2).strip()
    return pairs


def _parse_welf_attributes(attr_str):
    """Parse key="val" or key=val pairs from WELF."""
    pairs = {}
    for m in re.finditer(r'(\w+)="([^"]*)"', attr_str):
        pairs[m.group(1)] = m.group(2)
    for m in re.finditer(r'(\w+)=(\S+)', attr_str):
        if m.group(1) not in pairs:
            pairs[m.group(1)] = m.group(2)
    return pairs


# =============================================================================
# Main parser
# =============================================================================

def parse_log(log):
    """
    Try each syslog format in priority order.
    Returns a dict with at minimum:
        format    : string identifying which format matched
        message   : the actual log message payload
        timestamp : timestamp string (if present)
        hostname  : source hostname (if present)
        process   : process/appname (if present)
        pid       : process ID string (if present)
    Plus any format-specific extra fields.
    Returns None if nothing matched at all.
    """
    if not log or not log.strip():
        return None

    log = log.strip()

    # 1. RFC 5424 full
    m = RFC5424.match(log)
    if m:
        return {'format': 'RFC5424', **_clean(m.groupdict())}

    # 2. RFC 5424 no structured data
    m = RFC5424_NOSD.match(log)
    if m:
        d = _clean(m.groupdict())
        d['format'] = 'RFC5424_NOSD'
        d.setdefault('structured_data', '')
        return d

    # 3. RFC 3164 with PRI prefix
    m = RFC3164_PRI.match(log)
    if m:
        return {'format': 'RFC3164_PRI', **_clean(m.groupdict())}

    # 4. Cisco IOS — must come before RFC3164 (starts with * or sequence number)
    m = CISCO_IOS.match(log)
    if m:
        return {'format': 'CISCO_IOS', **_clean(m.groupdict())}

    # 5. Cisco ASA/FTD
    m = CISCO_ASA.match(log)
    if m:
        return {'format': 'CISCO_ASA', **_clean(m.groupdict())}

    # 6. No-host RFC3164 — must come BEFORE RFC3164 (pid brackets required)
    #    Mar  7 01:25:47 cron[999]: job started
    m = NO_HOST_RFC3164.match(log)
    if m:
        return {'format': 'NO_HOST_RFC3164', 'hostname': '', **_clean(m.groupdict())}

    # 7. RFC 3164 without PRI  (kernel: lines correctly parsed here too)
    m = RFC3164.match(log)
    if m:
        d = _clean(m.groupdict())
        d['format'] = 'RFC3164'
        # Tag kernel messages for convenience
        if d.get('process') == 'kernel':
            d['format'] = 'RFC3164_KERNEL'
        return d

    # 8. Junos — must come BEFORE ISO8601 (same timestamp, but has extra mnemonic field)
    m = JUNOS.match(log)
    if m:
        return {'format': 'JUNOS', **_clean(m.groupdict())}

    # 9. ISO 8601 with timezone offset
    m = ISO8601.match(log)
    if m:
        return {'format': 'ISO8601', **_clean(m.groupdict())}

    # 10. ISO 8601 UTC (Z suffix)
    m = ISO8601_UTC.match(log)
    if m:
        return {'format': 'ISO8601_UTC', **_clean(m.groupdict())}

    # 11. ISO 8601 no timezone
    m = ISO8601_NOTZ.match(log)
    if m:
        return {'format': 'ISO8601_NOTZ', **_clean(m.groupdict())}

    # 12. Syslog with year prepended
    m = SYSLOG_WITH_YEAR.match(log)
    if m:
        d = _clean(m.groupdict())
        d['format'] = 'SYSLOG_WITH_YEAR'
        d['timestamp'] = d.pop('year') + ' ' + d['timestamp']
        return d

    # 13. Windows Event Log
    m = WINDOWS_EVT.match(log)
    if m:
        return {'format': 'WINDOWS_EVT', **_clean(m.groupdict())}

    # 14. CEF
    m = CEF.match(log)
    if m:
        d = _clean(m.groupdict())
        d['format'] = 'CEF'
        d['extension_parsed'] = _parse_cef_extension(d.get('extension', ''))
        d['message'] = d.get('name', '')   # CEF "Name" field is the human-readable event
        return d

    # 15. LEEF
    m = LEEF.match(log)
    if m:
        d = _clean(m.groupdict())
        d['format'] = 'LEEF'
        d['attributes_parsed'] = _parse_leef_attributes(d.get('attributes', ''))
        d['message'] = d.get('event_id', '')
        return d

    # 16. WELF
    m = WELF.match(log)
    if m:
        d = _clean(m.groupdict())
        d['format'] = 'WELF'
        d['attributes_parsed'] = _parse_welf_attributes(d.get('attributes', ''))
        return d

    # 17. Kernel dmesg [ uptime ] message
    m = DMESG.match(log)
    if m:
        return {'format': 'DMESG', 'process': 'kernel',
                'hostname': '', 'timestamp': '', 'pid': '',
                **_clean(m.groupdict())}

    # 18. Process-only (process[pid]: message)
    m = PROCESS_ONLY.match(log)
    if m:
        return {'format': 'PROCESS_ONLY', 'hostname': '', 'timestamp': '',
                **_clean(m.groupdict())}

    # 19. Last resort fallback
    m = FALLBACK.match(log)
    if m:
        return {'format': 'FALLBACK', 'hostname': '', 'timestamp': '',
                **_clean(m.groupdict())}

    # Nothing matched at all — return raw as message
    return {'format': 'UNKNOWN', 'hostname': '', 'timestamp': '',
            'process': '', 'pid': '', 'message': log}