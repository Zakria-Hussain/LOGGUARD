"""Run the agent, the fixed rules and the LLM-with-no-tools over eval/scenarios.json,
score every answer (substring matching on lowercased text) and write eval/results.md.

Scoring per question: found = every expect_contains token appears in the answer;
false alarm = some expect_absent token appears; correct = found and no false alarm.
Substring matching is crude on purpose (it lets '198.51.100.1' match the whole
198.51.100.10-21 block), but it also means a '12' can match inside an IP - take the
summary numbers as an order of magnitude, the per-question table is the real result.

Slow + resumable: saves after every question to eval/progress.json, so a rate-limit
crash in the middle does not lose the run.
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv

import baseline_llm
import baseline_rules
from logguard import graph

SCEN = json.loads(Path('eval/scenarios.json').read_text(encoding='utf-8'))
CKPT = Path('eval/progress.json')
OUT = Path('eval/results.md')


def load_ckpt():
    if CKPT.exists():
        return json.loads(CKPT.read_text(encoding='utf-8'))
    return {'rows': []}


def save_ckpt(data):
    CKPT.write_text(json.dumps(data), encoding='utf-8')


def score(text, scen):
    low = (text or '').lower()
    found = all(tok.lower() in low for tok in scen['expect_contains'])
    alarm = any(tok.lower() in low for tok in scen['expect_absent'])
    return found, alarm


def safe(fn, q):
    """One question, retried - the free tier throws 413s and occasional 400s."""
    for attempt in range(3):
        try:
            return fn(q)
        except Exception as e:
            print(f'    {type(e).__name__}, attempt {attempt + 1}: {str(e)[:120]}', flush=True)
            time.sleep(60 * (attempt + 1))
    return '(system failed 3 times)'


def main():
    load_dotenv()
    ckpt = load_ckpt()
    rows = ckpt['rows']
    done = {r['id'] for r in rows}

    systems = {
        'rules': baseline_rules.answer,
        'llm': baseline_llm.answer,
        'agent': lambda q: graph.answer(q)['report'],
    }

    for scen in SCEN:
        if scen['id'] in done:
            continue
        row = {'id': scen['id'], 'category': scen['category'], 'q': scen['q'],
               'expect_contains': scen['expect_contains'], 'expect_absent': scen['expect_absent']}
        for name, fn in systems.items():
            t0 = time.time()
            text = safe(fn, scen['q'])
            found, alarm = score(text, scen)
            row[name] = {'found': found, 'false_alarm': alarm, 'answer': text[:600]}
            print(f"[{scen['id']:2d}] {name:5s} found={found} false_alarm={alarm} "
                  f"({time.time() - t0:.0f}s)", flush=True)
            time.sleep(3)
        rows.append(row)
        save_ckpt({'rows': rows})
        time.sleep(15)   # free tier TPM

    write_report(rows)


def mark(r, name):
    if name not in r:
        return '-'
    if r[name]['false_alarm']:
        return 'FA'
    return 'ok' if r[name]['found'] else 'MISS'


def write_report(rows):
    by = {name: [r for r in rows if name in r] for name in ['agent', 'rules', 'llm']}
    out = ['# LogGuard evaluation results\n']
    out.append(f'{len(rows)} questions over the synthetic log (answers known from '
               '`data/truth.json`). Same model everywhere (gpt-oss-20b, temperature 0). '
               'Scoring is substring matching on the answer text: found = every expected '
               'token appears, false alarm = a forbidden token appears (an IP named as the '
               'culprit that is actually innocent). Crude but reproducible.\n')

    out.append('| System | Correct | False alarms |')
    out.append('|---|---|---|')
    for name, label in [('agent', 'Agent (tools + verifier)'), ('rules', 'Fixed rules (grep-style)'),
                        ('llm', 'LLM, last 150 lines, no tools')]:
        n = len(by[name])
        ok = sum(1 for r in by[name] if r[name]['found'] and not r[name]['false_alarm'])
        fa = sum(1 for r in by[name] if r[name]['false_alarm'])
        out.append(f'| {label} | {ok}/{n} | {fa} |')
    out.append('')

    out.append('## Per-question detail\n')
    out.append('| # | Category | Question | Agent | Rules | LLM no tools |')
    out.append('|---|---|---|---|---|---|')
    for r in rows:
        out.append(f"| {r['id']} | {r['category']} | {r['q'][:70]} "
                   f"| {mark(r, 'agent')} | {mark(r, 'rules')} | {mark(r, 'llm')} |")
    out.append('')

    out.append('## Failure examples (agent)\n')
    fails = [r for r in rows if 'agent' in r and (r['agent']['false_alarm'] or not r['agent']['found'])]
    if not fails:
        out.append('The agent answered every scenario in this run.')
    for r in fails[:3]:
        why = 'false alarm' if r['agent']['false_alarm'] else 'missed expected token'
        out.append(f"- **{r['q']}** ({why}, expected {r['expect_contains']}): "
                   f"{r['agent']['answer'][:250]}...")
    out.append('')

    # keep the "Real logs" section if real_logs.py already appended it
    if OUT.exists() and '## Real logs' in OUT.read_text(encoding='utf-8'):
        out.append('## Real logs' + OUT.read_text(encoding='utf-8').split('## Real logs', 1)[1])
    OUT.write_text('\n'.join(out), encoding='utf-8')
    print(f'\nwrote {OUT} ({len(rows)} questions)')


if __name__ == '__main__':
    main()
