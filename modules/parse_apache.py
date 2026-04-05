import re

def parse_log(log_message):
    """Parses an Apache access log message."""
    apache_regex_access = r'^(\S+) (\S+) (\S+) \[([\w:\/]+\s[+\-]\d{4})\] "(\S+)\s?(\S+)?\s?(\S+)?" (\d{3}|-) (\d+|-)\s?"?([^"]*)"?\s?"?([^"]*)?"?$'
    match = re.match(apache_regex_access, log_message, re.M | re.I)
    if match:
        return {
            'remote_host': match.group(1),
            'identity': match.group(2),
            'user': match.group(3),
            'timestamp': match.group(4),
            'request_method': match.group(5),
            'request_path': match.group(6),
            'http_version': match.group(7),
            'status_code': match.group(8),
            'bytes_transferred': match.group(9),
            'referer_url': match.group(10),
            'user_agent': match.group(11),
        }
    return None

