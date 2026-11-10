"""Baseline 1: fixed grep-style rules, no LLM.

It runs the SAME two checks for every question - flag IPs with more than FAIL_THRESHOLD
failed logins, and count how many of those ever got in - and answers every question with
that one list. This is exactly the limitation the agent is supposed to beat: no notion of
what was asked, no slow attacks (each slow IP stays under the threshold).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logguard import tools as T
from logguard.parser import load_log

FAIL_THRESHOLD = 10


def build_answer():
    df = T.DF
    fails = df[df.event == 'failed'].ip.value_counts()
    loud = fails[fails > FAIL_THRESHOLD]
    cor = [r for r in T.correlate() if r['ip'] in loud.index]
    parts = ['Fixed rules (same checks for every question):']
    if len(loud):
        parts.append('IPs with more than 10 failed logins: '
                     + ', '.join(f'{ip} ({n} failures)' for ip, n in loud.items()))
    else:
        parts.append('IPs with more than 10 failed logins: zero')
    if cor:
        parts.append('Flagged IPs that later logged in successfully: '
                     + ', '.join(f"{r['ip']} as {r['user']} at {r['success_ts']}" for r in cor))
    else:
        parts.append('Flagged IPs that later logged in successfully: zero')
    parts.append(f'Total failed logins in the log: {int(fails.sum())}')
    return '\n'.join(parts)


_ANSWER = None


def answer(question):
    global _ANSWER
    if _ANSWER is None:
        T.DF = load_log('data/auth.log', year=2026)
        _ANSWER = build_answer()
    return _ANSWER


if __name__ == '__main__':
    print(answer('any question gives the same output'))
