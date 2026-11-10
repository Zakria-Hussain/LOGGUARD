
import re
from datetime import datetime
import pandas as pd

# Regex pattern to match Failed and Accepted SSH logins
# Group 1: Month, 2: Day, 3: Time, 4: Host, 5: Result, 6: Method, 7: Invalid user flag, 8: User, 9: IP, 10: Port
LOG_PATTERN = re.compile(
    r'^([A-Za-z]{3})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\[\d+\]:\s+'
    r'(Failed|Accepted)\s+(\w+)\s+for\s+(invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)'
)

# Month lookup dictionary to convert month strings to integers
MONTH_DICT = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}


def to_ts(mon, day, time_str, year):
    # Convert month, day, and HH:MM:SS string to a datetime object
    month_val = MONTH_DICT.get(mon, 1)
    day_val = int(day)
    
    # Split time by colons
    time_split = time_str.split(':')
    hour = int(time_split[0])
    minute = int(time_split[1])
    second = int(time_split[2])
    
    return datetime(year, month_val, day_val, hour, minute, second)


def load_log(path, year=2026):
    """
    Read the SSH auth log file, filter out irrelevant lines,
    and parse Failed/Accepted logins into a pandas DataFrame.
    """
    rows = []
    
    # Read file line by line
    with open(path, mode='r', encoding='utf-8', errors='replace') as f:
        line_count = 1
        for line in f:
            clean_line = line.rstrip('\n')
            m = LOG_PATTERN.match(clean_line)
            
            if m is not None:
                # Grab groups by positional index
                mon = m.group(1)
                day = m.group(2)
                t_str = m.group(3)
                host = m.group(4)
                res = m.group(5).lower()
                method = m.group(6).lower()
                inv_match = m.group(7)
                user = m.group(8)
                ip = m.group(9)
                port = int(m.group(10))
                
                # Check if it was an invalid user attempt
                is_invalid = True if inv_match else False
                
                row_data = {
                    'line_no': line_count,
                    'ts': to_ts(mon, day, t_str, year),
                    'host': host,
                    'event': res,
                    'method': method,
                    'user': user,
                    'invalid_user': is_invalid,
                    'ip': ip,
                    'port': port,
                    'raw': clean_line,
                }
                rows.append(row_data)
                
            line_count += 1
            
    df = pd.DataFrame(rows)
    return df


if __name__ == '__main__':
    # Debug print
    df = load_log('data/auth.log', 2026)
    print("Total rows parsed:", len(df))
    print(df.head(3))
