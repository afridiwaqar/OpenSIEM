import re

def parse_log(log_message):
    """Parses an auth.log message."""
    auth_regex = r'^(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\[\]:]+)(?:\[(\d+)\])?:\s*(.*)'
    match = re.match(auth_regex, log_message, re.M | re.I)
    if match:
        print("In the Module, Got a Hit on the Match ", match)
        return {
            'timestamp': match.group(1),
            'hostname': match.group(2),
            'process': match.group(3),
            'pid': match.group(4),
            'message': match.group(5),
        }
    return None

