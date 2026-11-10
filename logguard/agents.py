import json
import re

from . import tools as T

# Regex to match IPv4 addresses in findings
IP_PATTERN = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')

# Prompts for the agents in our pipeline
INVESTIGATOR_SYSTEM = (
    "You are the Investigator agent. Your job is to analyze SSH authentication logs "
    "to answer security questions.\n"
    "Use the available tools to query the log data. Never guess or fabricate information.\n"
    "When you have found sufficient evidence, respond with ONLY a JSON object formatted as:\n"
    '{"findings": ["fact 1", "fact 2"], "cited_lines": [105, 402]}\n'
    "The cited_lines MUST be the exact line numbers from the log file that back your findings.\n"
    "Do not include any other markdown or conversational text outside this JSON."
)

REPORTER_SYSTEM = (
    "You are the Reporter agent. You receive verified findings and cited raw log evidence.\n"
    "Create a clear incident report and reply with ONLY a JSON object:\n"
    '{"summary": "Brief 2-4 sentence overview", '
    '"findings": ["finding text quoting raw lines", ...], '
    '"severity": "Low|Medium|High|Critical", '
    '"action": "Recommended next step"}\n'
    "Severity Guidelines:\n"
    "- Critical: Confirmed unauthorized successful login.\n"
    "- High: Heavy brute force attempts from an IP with no success.\n"
    "- Medium: Distributed or slow scanning activity.\n"
    "- Low: Normal benign activity or minor user typos."
)

VERIFIER_RETRY_TEMPLATE = (
    "Your findings failed verification against the real log file. "
    "Please review these issues and reply with a corrected JSON object "
    "({{'findings': [...], 'cited_lines': [...]}}):\n{problems}"
)


# Allowed severity values the reporter may emit
ALLOWED_SEVERITIES = ['Low', 'Medium', 'High', 'Critical']


def shape_report(parsed, findings, raw_text):
    """
    Force the reporter reply into the report schema. parsed is the dict from
    extract_json (may be None or missing keys when the model ignored the JSON
    format). Always returns a complete report dict so the UI can rely on it.
    """
    if not isinstance(parsed, dict):
        parsed = {}

    # Only keep severity when the model used one of the allowed values
    severity = parsed.get('severity')
    if severity not in ALLOWED_SEVERITIES:
        severity = 'Unknown'

    # Fall back to the raw reply text (first 300 chars) when no summary exists
    if isinstance(parsed.get('summary'), str) and parsed['summary']:
        summary = parsed['summary']
    else:
        summary = (raw_text or '').strip()[:300] or '(no summary)'

    # Fall back to the verified findings, then to a placeholder
    rep_findings = parsed.get('findings')
    if not isinstance(rep_findings, list) or not rep_findings:
        rep_findings = findings or ['(no findings)']

    if isinstance(parsed.get('action'), str) and parsed['action']:
        action = parsed['action']
    else:
        action = 'none'

    return {'summary': summary, 'findings': rep_findings, 'severity': severity, 'action': action}


def extract_json(text):
    """
    Helper function to extract and parse JSON from the LLM's text output.
    Looks for the outer curly brackets {...} in case the model added extra text.
    """
    if not text:
        return None
        
    start = text.find('{')
    end = text.rfind('}')
    
    if start != -1 and end != -1 and end > start:
        candidate = text[start:end + 1]
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass
            
    # Try parsing text directly
    try:
        return json.loads(text.strip())
    except Exception:
        return None


def verify_findings(findings, cited_lines):
    """
    Deterministic Python verifier:
    Checks if cited line numbers exist in the log,
    and checks if every IP mentioned in findings actually appears in the cited lines.
    """
    problems = []
    
    if not findings:
        problems.append("no findings were returned")
        
    # Build dictionary mapping line_no to raw text from loaded DataFrame
    raw_lines_dict = {}
    for _, row in T.DF.iterrows():
        raw_lines_dict[int(row['line_no'])] = row['raw']
        
    cited_lines_text = []
    for num in cited_lines:
        if num in raw_lines_dict:
            cited_lines_text.append(raw_lines_dict[num])
        else:
            problems.append(f"cited line {num} does not exist in the log")
            
    # Cross-reference: verify that any IP address mentioned in findings appears in the evidence lines
    combined_evidence = ' '.join(cited_lines_text)
    for f in findings:
        ips_found = sorted(list(set(IP_PATTERN.findall(f))))
        for ip_addr in ips_found:
            if ip_addr not in combined_evidence:
                problems.append(f"IP {ip_addr} appears in a finding but in none of the cited lines")
                
    # Return formatted evidence list and problems list
    evidence_output = [f"line {n}: {raw_lines_dict[n]}" for n in cited_lines if n in raw_lines_dict]
    return evidence_output, problems
