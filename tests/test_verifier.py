from logguard import agents, tools as T
from logguard.parser import load_log

T.DF = load_log('data/auth.log', year=2026)


def test_fake_line_number_is_rejected():
    """LLMs invent line numbers - the verifier must catch one that is not in the log."""
    evidence, problems = agents.verify_findings(['IP 1.2.3.4 got in at 04:02'], [99999])
    assert any('99999' in p for p in problems)


def test_wrong_line_for_the_claim_is_rejected():
    """A real line that does not mention the claimed IP does not support the finding."""
    # line 2062 is a legit accepted login for 192.0.2.12, nothing to do with the attacker
    evidence, problems = agents.verify_findings(['IP 198.51.100.77 got in'], [2062])
    assert any('198.51.100.77' in p for p in problems)


def test_good_citation_passes():
    # line 803 is the real 04:02 accepted login from the attacker IP
    evidence, problems = agents.verify_findings(
        ['IP 198.51.100.77 logged in as deploy after 40 failures'], [803])
    assert problems == []
    assert len(evidence) == 1
    assert 'Accepted password for deploy from 198.51.100.77' in evidence[0]
