"""Run LogGuard on the real Loghub OpenSSH log (loghub_openssh.log, 2k lines, 2015).

These are logs the generator was not designed around, so this tests the parser and the
agent on data we do not control. Appends the three Q&A pairs to eval/results.md under
'Real logs' (run_eval.py keeps that section when it rewrites the file).
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv

from logguard import graph

QUESTIONS = [
    'Which IPs failed the most logins?',
    'Did anyone successfully log in? Quote the line.',
    'Was there a burst of failed logins from one IP, and is that IP different from the one that got in?',
]

OUT = Path(__file__).parent / 'results.md'


def main():
    load_dotenv()
    for attempt in range(3):
        try:
            blocks = []
            for q in QUESTIONS:
                t0 = time.time()
                state = graph.answer(q, log_path='data/loghub_openssh.log', year=2015)
                print(state['verdict'], state['retries'])   # debug, keep for now
                blocks.append(f'### Q: {q}\n\n{state["report"]}\n'
                              f'*(verifier: {state["verdict"]}, {time.time() - t0:.0f}s)*\n')
                print(f'ok: {q}', flush=True)
            break
        except Exception as e:
            print(f'attempt {attempt + 1} failed: {e}', flush=True)
            time.sleep(60)
    else:
        raise SystemExit('real logs run failed 3 times')

    text = OUT.read_text(encoding='utf-8') if OUT.exists() else ''
    if '## Real logs' in text:
        text = text.split('## Real logs')[0]
    text += ('## Real logs\n\nLoghub OpenSSH_2k.log (2,000 lines from a real server, 2015), '
             'same agent, no changes.\n\n' + '\n'.join(blocks))
    OUT.write_text(text, encoding='utf-8')
    print(f'appended to {OUT}')


if __name__ == '__main__':
    main()
