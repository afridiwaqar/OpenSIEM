# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024–present
# See LICENSE for details.

import logging
import re
import os
from datetime import datetime

import collector
import ipchecker
import correlation

from alarm_system import alarm_system


def _syslog_sev_to_alarm(syslog_sev: str) -> str:

    s = str(syslog_sev).lower().strip()
    if s in ('emerg', 'alert', 'crit', 'critical', 'fatal', 'panic'):
        return 'critical'
    if s in ('err', 'error', 'high'):
        return 'high'
    if s in ('warning', 'warn', 'mid', 'medium', 'notice'):
        return 'mid'
    return 'low'


def processMessage(conn, addr, module_dict, msg, conn_museum):
    if msg.startswith('<SystemStats>'):
        return

    log_regex = r'(\b\d{1,3}(?:\.\d{1,3}){3}\b)\s+(\S+)\s+(.*)'
    match = re.match(log_regex, msg)

    if not match:
        logging.warning(f"Invalid log format from {addr}")
        return

    source_ip, full_log_source, full_log = match.groups()

    if ipchecker.check_ip(match.group(0)):
        logging.critical(f"BLACKLISTED IP DETECTED: {source_ip}")

        matched_artifact = source_ip
        artifact_severity = 'high'
        try:
            import psycopg2, configparser as _cp
            _cfg = _cp.ConfigParser(); _cfg.read('/etc/opensiem/opensiem.conf')
            _d = _cfg['database']
            _conn = psycopg2.connect(host=_d['host'], database=_d['database'],
                                     user=_d['user'], password=_d['password'])
            _cur = _conn.cursor()
            _cur.execute("SELECT artifacts, severity FROM malicious_artifacts")
            _full_msg = match.group(0)
            for (_art, _sev) in _cur.fetchall():
                if _art and _art.lower() in _full_msg.lower():
                    matched_artifact = _art
                    artifact_severity = _sev or 'high'
                    break
            _cur.close(); _conn.close()
        except Exception as _e:
            logging.warning(f"Could not resolve matched artifact: {_e}")

        alarm_system.raise_alarm(
            case_name=f"Artifact detected: {matched_artifact}",
            source_ip=source_ip,
            severity=artifact_severity,
            details={"artifact": matched_artifact, "source_ip": source_ip,
                     "message": f"Malicious artifact '{matched_artifact}' found in log"},
            alert_type='artifact'
        )

    log_source = os.path.splitext(
        os.path.basename(full_log_source).replace("parse_", "")
    )[0]

    module = module_dict.get(log_source)
    if not module:
        logging.warning(f"No parser for log source: {log_source}")
        return

    parsed_log = module.parse_log(full_log) or {
        "timestamp": "N/A",
        "hostname": "",
        "process": "",
        "pid": 0,
        "message": full_log
    }

    msg_id = collector.get_message_id(conn_museum, parsed_log["message"])

    collector.museum(
        conn_museum,
        log_source,
        os.path.dirname(full_log_source),
        source_ip,
        str(addr[1]),
        datetime.now().strftime("%Y-%m-%d"),
        datetime.now().strftime("%H:%M:%S"),
        parsed_log.get("hostname", ""),
        parsed_log.get("process", ""),
        parsed_log.get("pid", 0),
        parsed_log["message"]
    )

    correlation.correlate(msg_id, parsed_log, source_ip=source_ip)
