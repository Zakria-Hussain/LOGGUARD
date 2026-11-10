# LogGuard

LogGuard answers questions about an SSH auth log. You type something like "Did any attacker eventually get in?" and it goes through the log, checks its own work, and writes a short incident report with a severity and a suggested action.

I built it for the final project of the atomcamp AI bootcamp (agentic AI track).

## The idea

Reading auth logs by hand is slow, and a plain grep script only answers the one question it was written for. A language model can answer any question, but if you paste in a few hundred lines it only sees those lines, and it will happily make up evidence.

So the model here does not read the log. It gets seven small pandas tools and decides which ones to call. Its answer then has to survive a check written in plain Python.

## How it works

The whole thing is one LangGraph graph with four steps:

1. **Investigator.** A tool-calling loop. It can call `filter_events`, `ip_profile`, `frequency_stats`, `top_ips`, `correlate`, `calculate` and `report_draft`, as many times as it wants.
2. **Extract.** Pulls out the findings and the log line numbers they rely on.
3. **Verifier.** Plain Python, no LLM. It checks that the cited lines exist and that every IP named in a finding appears in one of them. If something is off, the investigator gets the complaint and one more try. After that the answer goes through anyway.
4. **Reporter.** One LLM call that turns the findings into the report.

The model is `openai/gpt-oss-20b` on Groq. If Groq fails (rate limit, daily cap), the wrapper in `logguard/graph.py` falls back to OpenAI `gpt-5-mini`, but only when an OpenAI key is in `.env`.

## Running it

```
python -m venv .venv
.venv\Scripts\Activate.ps1     # in cmd just: .venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

Put your `GROQ_API_KEY` in `.env`. The OpenAI key is optional.

```
python data/generate_logs.py      # makes data/auth.log (about 2,900 lines)
pytest tests/ -q
python -m logguard.ask "Did any attacker eventually get in?"
streamlit run app.py              # same thing with a UI that shows each tool call
```

## Data

- `data/generate_logs.py` writes a fake auth log with a fixed seed. It plants four attacks on top of normal office logins: a burst of about 300 failed logins in ten minutes, a slow brute force from 12 IPs spread over the night, credential stuffing from 25 IPs, and one attacker who fails 40 times and then gets in. The answers are saved in `data/truth.json`. The IPs come from the reserved documentation ranges (203.0.113.x and so on), so none of them are real.
- `data/loghub_openssh.log` is the public Loghub OpenSSH sample, 2,000 lines from a real server. I use it to check the agent is not only working on logs I generated myself.

## How I tested it

There are 20 questions in `eval/scenarios.json`, each with a known answer, and I ran three systems on them:

- the agent
- a fixed rule script (`eval/baseline_rules.py`) that flags IPs above a failure threshold
- the same model with the last 150 log lines and no tools (`eval/baseline_llm.py`)

`python eval/run_eval.py` runs all three and writes `eval/results.md`. It saves after every question, so if Groq's rate limit stops it halfway you can start it again. A full run takes about an hour on the free tier. The per-question table in `results.md` is the real result. The summary counts are rough.

Scoring is substring matching on the answer text, which is crude. For example, a "12" can match inside an IP address. I kept it because it is easy to reproduce.

`python eval/real_logs.py` asks three questions on the Loghub log and appends the answers to `results.md`.

## Where it fails

- It only parses `Failed password` and `Accepted password` lines. Other sshd messages (invalid user, preauth) are skipped. On the Loghub file about 523 of 2,000 lines parse.
- The verifier checks that citations exist and support the IPs named. It cannot tell whether a number in a finding is the right number.
- On the slow distributed attack and the credential-stuffing questions the agent often gets it wrong, and the results file shows which ones.
- It is not deterministic. On the real log, the same question can come back right once and wrong the next time, even at temperature 0.
- The attacks in the synthetic log are planted. Real attackers are messier.

One bug I hit while recording a demo: the agent asked `frequency_stats` for a `10m` window, and pandas reads a bare `m` as "month", so the run crashed. `tools.py` now turns `10m` into `10min`, and a window pandas still rejects comes back to the model as an error message instead of crashing the run. The eval run that produced the first results was done before this fix.


## Layout

```
app.py              Streamlit UI
logguard/
  parser.py         turns log lines into a pandas table
  tools.py          the seven tools
  graph.py          the LangGraph graph and the LLM wrapper
  agents.py         the prompts and the verifier
  ask.py            command-line entry point
eval/               questions, baselines, scoring
data/               log generator and the Loghub sample
tests/              parser, tools, verifier, fallback
```
