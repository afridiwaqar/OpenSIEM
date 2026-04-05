# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024–present
# See LICENSE for details.

import psycopg2
from datetime import datetime
import json

import configparser

config = configparser.ConfigParser()
config.read('/etc/opensiem/opensiem.conf')

db_server = config['database']['host']
db_port = config['database']['port']
db_db = config['database']['database']
db_user = config['database']['user']
db_password = config['database']['password']

#print("===========================>>>>>>>>>>>>>>>>>>>>>", db_user)

# def establish_connection():
#     conn = psycopg2.connect(
#         host="127.0.0.1",
#         database="museum",
#         user="waqar",
#         password="12345"
#     )
#     return conn

def establish_connection():
    conn = psycopg2.connect(
        host=db_server,
        database=db_db,
        user=db_user,
        password=db_password
    )
    return conn


# source_name = "rsyslog"
# source_path = "/var/log/rsyslog"
# IP  = "127.0.0.1"
# Port = 60074
# date_stamp = "2023-05-15"
# time_stamp = "18:25:14"
# device_name = "WixSys"
# source_process = "systemd"
# source_pid = 3323
# message =  "vte-spawn-57595d53-b5e5-4ff2-a619-c2ef3611ec89.scope: Succeeded."


def museum(curr, source_name, source_path, IP, Port, date_stamp, time_stamp, device_name, source_process, source_pid, message):
    try:
        device_name = device_name if device_name else 'Unknown'
        source_process = source_process if source_process else 'Unknown'
        source_pid = int(source_pid) if source_pid else 0
        message = message if message is not None else "Blank Message"

        cur = curr.cursor()
        curr.rollback()
        curr.autocommit = False

        # current_date = datetime.now().date()

        # cur.execute("UPDATE Calendar SET time = %s", (current_time,))
        cur.execute("INSERT INTO Calendar (Date, time) VALUES (%s, %s) RETURNING data_id", (date_stamp, time_stamp))
        # cur.execute("INSERT INTO Calendar (Date) VALUES (%s) RETURNING data_id", (current_date,))
        data_id = cur.fetchone()[0]

        cur.execute("INSERT INTO \"Log_Source\" (source_name, source_path) VALUES (%s, %s) RETURNING source_id",
                    (source_name, source_path))
        source_id = cur.fetchone()[0]

        cur.execute("INSERT INTO Device (device_name, device_ip, device_port) VALUES (%s, %s, %s) RETURNING device_id",
                    (device_name, IP, str(Port)))
        device_id = cur.fetchone()[0]

        cur.execute("INSERT INTO Process (process_name, pid) VALUES (%s, %s) RETURNING process_id",
                    (source_process, str(source_pid)))
        process_id = cur.fetchone()[0]

        cur.execute("INSERT INTO Message (message_source, Date, message, log_source, device_id, process_id) "
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    (source_id, data_id, json.dumps({"message": message}), source_id, device_id, process_id))

        curr.commit()
        curr.autocommit = True

    except Exception as e:
        curr.rollback()
        curr.autocommit = True
        print(f"An error occurred: {str(e)}")
    finally:
        cur.close()


def malicious_artifacts_checker(curr, mal_msg):
    cur = curr.cursor()
    cur.execute("SELECT artifacts FROM malicios_artifacts")

    artifacts_list = [row[0] for row in cur.fetchall()]
    matching_strings = [artifact for artifact in artifacts_list if mal_msg in artifact]
    # print("-------------------------------- Found an artifact ------------------------------")

    for string in matching_strings:
        print("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW ---> ", string)

    cur.close()


def get_message_id(curr, msg):
    print("CHECKing Correlation for ...... --> ", msg)
    cur = curr.cursor()

    cur.execute("SELECT msg_id, message FROM special_messages;")
    rows = cur.fetchall()
    cur.close()

    msg_lower = msg.lower()
    for msg_id, pattern in rows:
        if pattern and pattern.lower() in msg_lower:
            print("Message found at -----> ", msg_id, " pattern=", repr(str(pattern)[:60]))
            return msg_id

    print("No message for correlation")
    return None
