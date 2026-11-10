import json
from pathlib import Path

import pytest

from logguard import tools
from logguard.parser import load_log

TRUTH = json.loads(Path('data/truth.json').read_text(encoding='utf-8'))
tools.DF = load_log('data/auth.log', year=2026)


def test_correlate_finds_the_breakin():
    """The attacker IP failed ~40 times and then logged in - correlate() must see it.
    The burst IP never logged in successfully, so it must not be there."""
    ips = {r['ip']: r for r in tools.correlate()}
    assert '198.51.100.77' in ips
    assert ips['198.51.100.77']['failures_before'] >= 30
    assert ips['198.51.100.77']['user'] == 'deploy'
    assert '203.0.113.50' not in ips


def test_correlate_strong_vs_weak_candidates():
    """The attacker correlates with 40 failures. An office IP with one typo can also
    correlate, but with exactly 1 failure - that is how the agent tells them apart.
    Attack IPs without a success (burst) never appear."""
    out = tools.correlate()
    ips = {r['ip']: r for r in out}
    assert ips['198.51.100.77']['failures_before'] == 40
    assert ips['198.51.100.77']['user'] == 'deploy'
    for ip, r in ips.items():
        if ip != '198.51.100.77':
            assert r['failures_before'] == 1
    assert '203.0.113.50' not in ips
    assert not (set(ips) & set(TRUTH['slow']['ips']))


def test_frequency_top_window_is_the_burst():
    stats = tools.frequency_stats('failed', '10min', top=5)
    assert stats['windows'][0]['window_start'] == '2026-10-28 01:30:00'
    # ~300 burst failures; a slow-attack failure can land in the same 10 minutes
    assert stats['windows'][0]['count'] >= TRUTH['burst']['failed']


def test_ip_profile_burst():
    p = tools.ip_profile('203.0.113.50')
    assert p['failed'] == TRUTH['burst']['failed']
    assert p['accepted'] == 0
    assert sorted(p['users_tried']) == ['admin', 'root', 'test']


def test_filter_events_by_ip():
    r = tools.filter_events(event='accepted', ip='198.51.100.77')
    assert r['total_matches'] == 1
    assert r['rows'][0]['user'] == 'deploy'
    assert r['rows'][0]['ts'].startswith('2026-10-28 04:02:11')


def test_calculate():
    assert tools.calculate('72/48')['result'] == 1.5
    assert tools.calculate('300*4')['result'] == 1200
    assert tools.calculate('2**10')['result'] == 1024


def test_calculate_refuses_code():
    with pytest.raises(ValueError):
        tools.calculate("__import__('os')")
    with pytest.raises(ValueError):
        tools.calculate('df.head()')


def test_report_draft():
    md = tools.report_draft(['IP 1.2.3.4 got in at 04:02 (line 402)'], 'Critical', 'Block the IP')
    assert '# LogGuard incident report' in md
    assert '**Severity: Critical**' in md
    assert 'Block the IP' in md
