#!/usr/bin/env python3
# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024–present
# See LICENSE for details.

import smtplib
import configparser
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import threading
from collections import defaultdict
import json
import psycopg2
import secrets

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("alarm_system")

class AlarmSystem:

    def __init__(self):
        cfg = configparser.ConfigParser()
        cfg.read('/etc/opensiem/opensiem.conf')

        self.db = cfg['database']

        em = cfg['email'] if 'email' in cfg else {}
        self.email_enabled   = cfg.getboolean('email', 'enabled', fallback=False)
        self.smtp_server     = cfg.get('email', 'smtp_server', fallback='')
        self.smtp_port       = cfg.getint('email', 'smtp_port', fallback=587)
        self.sender_email    = cfg.get('email', 'sender_email', fallback='')
        self.sender_password = cfg.get('email', 'sender_password', fallback='')
        self.admin_emails    = [e.strip() for e in cfg.get('email', 'admin_emails', fallback='').split(',') if e.strip()]
        self.use_tls         = cfg.getboolean('email', 'use_tls', fallback=True)

        self.email_severities = [s.strip().lower() for s in cfg.get('alerts', 'email_severities', fallback='high,critical').split(',')]
        self.ui_severities    = [s.strip().lower() for s in cfg.get('alerts', 'ui_severities',    fallback='low,mid,high,critical').split(',')]
        self._severity_alias  = {'medium': 'mid'}
        self.cooldown_period  = cfg.getint('alerts', 'cooldown_period', fallback=300)

        self.ui_notifications = []
        self.ui_lock = threading.Lock()

        self.stats = {
            'total_alerts': 0,
            'email_sent': 0,
            'ui_notifications': 0,
            'by_severity': defaultdict(int),
            'by_type': defaultdict(int)
        }

        log.info("Alarm system initialized. Email enabled: %s", self.email_enabled)
        log.info("Email severities: %s", self.email_severities)
        log.info("UI severities: %s", self.ui_severities)

    def _conn(self):
        return psycopg2.connect(
            host=self.db['host'],
            database=self.db['database'],
            user=self.db['user'],
            password=self.db['password']
        )

    def _normalize_severity(self, severity: str) -> str:
        if not severity:
            return 'mid'
        return self._severity_alias.get(severity.lower(), severity.lower())

    def _build_admin_note(self, case_name: str, details) -> str:
        payload = {
            "case_name": case_name,
            "details": details or {},
            "created_at": datetime.utcnow().isoformat()
        }
        try:
            return json.dumps(payload, ensure_ascii=False)
        except Exception:
            return f"case_name={case_name}; details={details}"

    def _generate_alert_id(self, prefix: str = "AL") -> str:
        return prefix + secrets.token_hex(6).upper()

    def _send_email_notification(self, subject: str, body: str, severity: str) -> bool:
        if not self.email_enabled or not self.admin_emails or not self.sender_email:
            return False
        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To']   = ', '.join(self.admin_emails)
            msg['Subject'] = f"🚨 Security Alert: {subject} ({severity.upper()})"

            html = f"""
            <html><body style="font-family:Arial,sans-serif;line-height:1.6;">
              <div style="background-color:#cc3333;color:#fff;padding:14px;border-radius:5px;">
                <h3 style="margin:0;">Security Alert: {severity.upper()}</h3>
              </div>
              <pre style="background:#f7f7f7;border-left:4px solid #ccc;padding:12px;white-space:pre-wrap;">{body}</pre>
            </body></html>
            """
            msg.attach(MIMEText(html, 'html'))

            with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=10) as server:
                if self.use_tls:
                    server.starttls()
                if self.sender_password:
                    server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            self.stats['email_sent'] += 1
            return True
        except Exception as e:
            log.warning("Email send failed: %s", e)
            return False

    def _find_existing_alert(self, cur, alert_type: str, case_name: str, source_ip: str):
        """
        Find an active alert row for the same (type, case_name, source_ip).
        We search case_name inside admin_note JSON text (no schema change).
        """
        like_pattern = f'%\\"case_name\\":\\"{case_name}\\"%'
        cur.execute(
            """
            SELECT id, count
              FROM alerts
             WHERE is_active = TRUE
               AND alert_type = %s
               AND COALESCE(source_ip::text,'') = COALESCE(%s::text,'')
               AND admin_note LIKE %s
             ORDER BY id DESC
             LIMIT 1
            """,
            (alert_type, source_ip, like_pattern)
        )
        return cur.fetchone()

    def _insert_occurrence_summary(self, cur, alert_id: int, fk_msg_id, source_ip: str, admin_note_json: str):
        cur.execute(
            """
            INSERT INTO alert_occurrences (alert_id_fk, occurred_at, fk_msg_id, source_ip, details)
            VALUES (%s, NOW(), %s, %s, %s)
            """,
            (alert_id, fk_msg_id, source_ip, admin_note_json)
        )

    def raise_alarm(
        self,
        case_name: str,
        source_ip: str | None = None,
        severity: str = "mid",
        details: dict | str | None = None,
        alert_type: str = "correlation",
        fk_msg_id: int | None = None
    ) -> dict:

        sev = self._normalize_severity(severity)
        admin_note_json = self._build_admin_note(case_name, details)
        external_alert_id = None

        conn = self._conn()
        try:
            cur = conn.cursor()

            found = self._find_existing_alert(cur, alert_type, case_name, source_ip)
            if found:
                existing_id, count = found
                cur.execute(
                    "UPDATE alerts SET count = %s WHERE id = %s",
                    (count + 1, existing_id)
                )
                self._insert_occurrence_summary(cur, existing_id, fk_msg_id, source_ip, admin_note_json)
                conn.commit()
                log.info("Alert consolidated id=%s type=%s case=%s src=%s", existing_id, alert_type, case_name, source_ip)
                self.stats['total_alerts'] += 1
                self.stats['by_severity'][sev] += 1
                self.stats['by_type'][alert_type] += 1
                return {"id": existing_id, "alert_id": None, "consolidated": True}

            external_alert_id = self._generate_alert_id("AL")
            cur.execute(
                """
                INSERT INTO alerts
                    (alert_id, alert_type, severity, is_active, count, source_ip, admin_note, fk_msg_id)
                VALUES
                    (%s,       %s,         %s,       TRUE,      1,     %s,        %s,         %s)
                RETURNING id
                """,
                (external_alert_id, alert_type, sev, source_ip, admin_note_json, fk_msg_id)
            )
            new_id = cur.fetchone()[0]

            self._insert_occurrence_summary(cur, new_id, fk_msg_id, source_ip, admin_note_json)

            conn.commit()
            log.info("Alert created id=%s alert_id=%s type=%s sev=%s src=%s",
                     new_id, external_alert_id, alert_type, sev, source_ip)

            self.stats['total_alerts'] += 1
            self.stats['by_severity'][sev] += 1
            self.stats['by_type'][alert_type] += 1

            if sev in self.email_severities:
                try:
                    subject = f"{case_name} [{alert_type}]"
                    body = admin_note_json
                    self._send_email_notification(subject, body, sev)
                except Exception as e:
                    log.debug("Email attempt failed (non-fatal): %s", e)

            return {"id": new_id, "alert_id": external_alert_id, "consolidated": False}

        except Exception as e:
            conn.rollback()
            log.exception("raise_alarm failed: %s", e)
            return {"id": None, "alert_id": None, "error": str(e)}
        finally:
            try:
                cur.close()
            except Exception:
                pass
            conn.close()
            
alarm_system = AlarmSystem()

def raise_alarm(
    case_name: str,
    source_ip: str | None = None,
    severity: str = "mid",
    details: dict | str | None = None,
    alert_type: str = "correlation",
    fk_msg_id: int | None = None
) -> dict:
    return alarm_system.raise_alarm(case_name, source_ip, severity, details, alert_type, fk_msg_id)
