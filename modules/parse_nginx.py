import re

def parse_log(log_message):
    """Parses an Nginx log message."""
    nginx_regex = r'^(\S+) (\S+) (\S+) \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)" ([^"]*) ([^"]*) ([^"]*) "([^"]*)" "([^"]*)"'
    match = re.match(nginx_regex, log_message, re.M | re.I)
    if match:
        return {
            'remote_addr': match.group(1),
            'remote_user': match.group(2),
            'time_local': match.group(4),
            'request_method': match.group(5),
            'request_uri': match.group(6),
            'protocol': match.group(7),
            'status': match.group(8),
            'body_bytes_sent': match.group(9),
            'http_referer': match.group(10),
            'http_user_agent': match.group(11),
            # ... add other fields as needed ...
        }
    return None

