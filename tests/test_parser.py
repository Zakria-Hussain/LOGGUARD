from datetime import datetime

from logguard.parser import load_log

DF = load_log('data/auth.log', year=2026)


def test_row_count_matches_file():
    """Every Failed/Accepted line in the file must become exactly one row."""
    with open('data/auth.log', encoding='utf-8') as f:
        expected = sum(1 for line in f if 'Failed password' in line or 'Accepted password' in line)
    assert len(DF) == expected


def test_breakin_success_row():
    """The 04:02:11 success is the attacker IP logging in as deploy."""
    row = DF[DF.ts == datetime(2026, 10, 28, 4, 2, 11)].iloc[0]
    assert row.event == 'accepted'
    assert row.ip == '198.51.100.77'
    assert row.user == 'deploy'


def test_raw_keeps_the_file_line():
    """raw of row N must be exactly line N of the file (Verifier relies on this)."""
    for _, row in DF.sample(20, random_state=1).iterrows():
        with open('data/auth.log', encoding='utf-8') as f:
            line = f.readlines()[row.line_no - 1].rstrip('\n')
        assert row.raw == line


def test_skips_noise_lines():
    assert not DF.raw.str.contains('Connection closed|CRON', regex=True).any()


def test_columns_and_types():
    for col in ['line_no', 'ts', 'host', 'event', 'method', 'user', 'invalid_user', 'ip', 'port', 'raw']:
        assert col in DF.columns
    assert DF.ts.iloc[0].year == 2026
