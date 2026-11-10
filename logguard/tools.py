
import re
import pandas as pd

# Global DataFrame variable that holds the parsed log rows
# This gets loaded by graph.py or app.py before running queries
DF = None

COLS = ['line_no', 'ts', 'event', 'user', 'ip']


def filter_events(event=None, user=None, ip=None, start=None, end=None, limit=50):
    """
    Filter the parsed log DataFrame based on event type, username, IP address,
    or start/end date-time range. Caps result to limit (default 50).
    """
    filtered = DF.copy()
    
    # Filter by event (failed / accepted)
    if event:
        filtered = filtered[filtered['event'] == event]
        
    # Filter by user
    if user:
        filtered = filtered[filtered['user'] == user]
        
    # Filter by IP
    if ip:
        filtered = filtered[filtered['ip'] == ip]
        
    # Filter by start timestamp
    if start:
        start_ts = pd.to_datetime(start, errors='coerce')
        if pd.notna(start_ts):
            filtered = filtered[filtered['ts'] >= start_ts]
            
    # Filter by end timestamp
    if end:
        end_ts = pd.to_datetime(end, errors='coerce')
        if pd.notna(end_ts):
            filtered = filtered[filtered['ts'] <= end_ts]
            
    # Set maximum limit so output fits in LLM prompt context
    max_rows = 50
    if limit is not None:
        try:
            val = int(limit)
            if val < max_rows:
                max_rows = val
        except (ValueError, TypeError):
            max_rows = 50
            
    subset = filtered.head(max_rows)[COLS].copy()
    subset['ts'] = subset['ts'].astype(str)
    
    return {
        'total_matches': int(len(filtered)),
        'rows': subset.to_dict(orient='records')
    }


def ip_profile(ip):
    """
    Get full activity summary for a single IP address:
    total failures, total accepted logins, list of users tried, and first/last seen.
    """
    ip_subset = DF[DF['ip'] == ip]
    if len(ip_subset) == 0:
        return {'error': f'no events for {ip}'}
        
    accepted_df = ip_subset[ip_subset['event'] == 'accepted']
    failed_df = ip_subset[ip_subset['event'] == 'failed']
    
    # Check if this IP ever had a successful login
    first_success = None
    if len(accepted_df) > 0:
        first_success = str(accepted_df['ts'].min())
        
    user_list = sorted(list(ip_subset['user'].unique()))
    
    return {
        'ip': ip,
        'failed': int(len(failed_df)),
        'accepted': int(len(accepted_df)),
        'users_tried': user_list,
        'first_seen': str(ip_subset['ts'].min()),
        'last_seen': str(ip_subset['ts'].max()),
        'first_success': first_success,
    }


def frequency_stats(event='failed', window='1h', top=5):
    """
    Find time windows with the highest count of failed or accepted attempts.
    Useful for spotting brute force bursts.
    """
    event_df = DF[DF['event'] == event]

    # The model often writes minutes as "10m". Pandas reads a bare "m" as
    # month-end and raises, so turn minute-style strings into "10min".
    window = re.sub(r'^\s*(\d+)\s*(m|mins?|minutes?)\s*$', r'\1min', str(window), flags=re.I)

    # Resample by window frequency using pd.Grouper
    try:
        window_counts = event_df.groupby(pd.Grouper(key='ts', freq=window)).size()
    except ValueError as e:
        # Never let a bad window kill the whole investigation - return the error
        # so the model can just retry with a different format
        return {'error': f'invalid window "{window}": {e}. Use formats like 10min, 1h, 1d'}

    top_counts = window_counts[window_counts > 0].sort_values(ascending=False).head(top)
    
    output = []
    for win_start, count in top_counts.items():
        output.append({
            'window_start': str(win_start),
            'count': int(count)
        })
        
    return {
        'event': event,
        'window': window,
        'windows': output
    }


def top_ips(event='failed', n=5):
    """
    Return top N IPs with the highest event count (failed or accepted logins).
    """
    event_df = DF[DF['event'] == event]
    ip_counts = event_df['ip'].value_counts().head(n)
    
    result = []
    for ip_val, cnt in ip_counts.items():
        result.append({
            'ip': ip_val,
            'count': int(cnt)
        })
        
    return {
        'event': event,
        'ips': result
    }


def correlate():
    """
    Detect break-in pattern: find any IP that had failed login attempts
    and subsequently had an accepted login.
    """
    candidates = []
    
    # Group by IP address to check each IP's history
    for ip_address, ip_df in DF.groupby('ip'):
        accepted = ip_df[ip_df['event'] == 'accepted']
        
        # Did this IP manage to log in successfully?
        if not accepted.empty:
            first_success_time = accepted['ts'].min()
            
            # Count failed attempts that happened strictly before the success
            failed = ip_df[ip_df['event'] == 'failed']
            failures_before = 0
            
            for _, r in failed.iterrows():
                if r['ts'] < first_success_time:
                    failures_before += 1
                    
            if failures_before > 0:
                first_acc_user = accepted.iloc[0]['user']
                candidates.append({
                    'ip': ip_address,
                    'failures_before': failures_before,
                    'success_ts': str(first_success_time),
                    'user': first_acc_user
                })
                
    # Sort by number of failures in descending order so worst offenders are first
    candidates.sort(key=lambda x: x['failures_before'], reverse=True)
    return candidates[:20]


def calculate(expression):
    """
    Helper tool to let the agent do basic math (rates, percentages).
    Performs security checks to prevent dangerous code execution.
    """
    expr = str(expression).strip()
    
    # Block dangerous identifiers
    blocked = ['__', 'import', 'os', 'sys', 'df', 'open', 'exec', 'eval', 'subprocess']
    for keyword in blocked:
        if keyword in expr.lower():
            raise ValueError(f"Code execution is not allowed: '{keyword}'")
            
    # Whitelist characters allowed in basic arithmetic
    allowed_chars = "0123456789+-*/.%() "
    for char in expr:
        if char not in allowed_chars:
            raise ValueError(f"Invalid character in math expression: {char}")
            
    try:
        # Evaluate safely without builtins
        val = eval(expr, {"__builtins__": {}}, {})
        return {'expression': expr, 'result': val}
    except Exception as e:
        raise ValueError(f"Calculation failed: {e}")


def report_draft(findings, severity, action):
    """
    Generate the final markdown report from findings, severity, and recommendations.
    """
    lines = [
        '# LogGuard incident report',
        '',
        f'**Severity: {severity}**',
        '',
        '## Findings'
    ]
    
    for f in findings:
        lines.append(f'- {f}')
        
    lines.append('')
    lines.append('## Recommended action')
    lines.append(action)
    
    return '\n'.join(lines)
