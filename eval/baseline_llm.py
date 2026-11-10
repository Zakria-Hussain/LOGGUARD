"""Baseline 2: the same LLM with no tools - just the last 150 raw log lines pasted in.

The token limit is the point: a night of attacks does not fit in the context window,
and whatever happened earlier in the log is simply not visible to the model.
"""
import re
import time
from pathlib import Path

from groq import RateLimitError
from langchain_groq import ChatGroq

TAIL_LINES = 150

PROMPT = ('You are a security analyst. Here are the last {n} lines of an SSH auth log:\n\n'
          '{log}\n\nQuestion: {q}\n'
          'Answer using only these lines. If the log does not contain the answer, say so.')


def safe_invoke(llm, prompt):
    """Invoke, backing off when the Groq free-tier TPM limit kicks in."""
    waits = [15, 30, 45, 60, 90, 120]
    for wait in waits:
        try:
            return llm.invoke(prompt)
        except RateLimitError as e:
            m = re.search(r'try again in ([0-9.]+)s', str(e))
            w = float(m.group(1)) + 3 if m else wait
            w = max(w, wait)
            print(f'    rate limited, waiting {w:.0f}s', flush=True)
            time.sleep(w)
    raise RuntimeError('rate limited too many times')


def tail(path='data/auth.log', n=TAIL_LINES):
    lines = Path(path).read_text(encoding='utf-8').splitlines()
    return '\n'.join(lines[-n:])


def answer(question, llm=None):
    llm = llm or ChatGroq(model='openai/gpt-oss-20b', temperature=0)
    log = tail()
    reply = safe_invoke(llm, PROMPT.format(n=TAIL_LINES, log=log, q=question))
    return reply.content


if __name__ == '__main__':
    from dotenv import load_dotenv
    load_dotenv()
    print(answer('Did any attacker eventually get in?'))
