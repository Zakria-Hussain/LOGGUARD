from logguard import agents, graph


def test_valid_parsed_dict_passes_through():
    """A well-formed reporter JSON keeps every field, severity included."""
    parsed = {
        'summary': 'Brute force attack detected.',
        'findings': ['40 failed logins from 198.51.100.77'],
        'severity': 'High',
        'action': 'Block the IP'
    }
    report = agents.shape_report(parsed, [], '')
    assert report == parsed


def test_plain_text_reply_becomes_unknown_severity():
    """No JSON at all: summary comes from raw text, findings from the argument."""
    report = agents.shape_report(None, ['finding one'], 'Looks like a brute force attack happened.')
    assert report['severity'] == 'Unknown'
    assert report['summary'] == 'Looks like a brute force attack happened.'
    assert report['findings'] == ['finding one']


def test_invalid_severity_becomes_unknown():
    """Severity strings outside the allowed list must not reach the report."""
    parsed = {'summary': 's', 'findings': ['f'], 'severity': 'SEVERE!!!', 'action': 'a'}
    assert agents.shape_report(parsed, [], '')['severity'] == 'Unknown'


def test_missing_findings_falls_back():
    """No findings anywhere gives the placeholder list."""
    report = agents.shape_report({}, [], 'some text')
    assert report['findings'] == ['(no findings)']


class FakeReply:
    def __init__(self, content):
        self.content = content


class PlainTextLLM:
    """Minimal fake model - reporter_node calls invoke without tools."""
    def invoke(self, messages, tools=None):
        return FakeReply('Looks like a brute force attack happened.')


def test_reporter_node_with_plain_text_reply():
    """The real reporter_node must always return schema-shaped report_data."""
    app = graph.build_graph(PlainTextLLM())
    reporter = app.nodes['reporter']
    result = reporter.invoke({
        'question': 'any attacks?',
        'findings': ['IP 198.51.100.77 made 40 failed attempts'],
        'evidence': [],
        'verifier_notes': ''
    })
    assert result['report_data']['severity'] == 'Unknown'
    assert 'LogGuard incident report' in result['report']
