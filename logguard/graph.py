import os
import time
from typing import Annotated, TypedDict

from dotenv import load_dotenv
from langchain_core.messages import HumanMessage
from langchain_core.tools import tool
from langchain_groq import ChatGroq
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from . import agents, tools as T
from .parser import load_log

# Primary and fallback model configurations
GROQ_MODEL = 'openai/gpt-oss-20b'
OPENAI_MODEL = 'gpt-5-mini'


class LogState(TypedDict):
    """
    State object shared across all nodes in the LangGraph workflow.
    Uses add_messages to append chat messages rather than overwriting.
    """
    question: str
    messages: Annotated[list, add_messages]
    findings: list
    cited_lines: list
    evidence: list
    verdict: str  # 'pass' or 'retry'
    verifier_notes: str
    retries: int
    report: str
    report_data: dict  # structured report fields so the UI can render a card


# ---------------- Tools wrapped with LangChain @tool decorator ----------------

@tool
def filter_events(event: str = None, user: str = None, ip: str = None,
                  start: str = None, end: str = None, limit: int = 25) -> dict:
    """Search login events in the log. event is 'failed' or 'accepted'.
    start/end are 'YYYY-MM-DD HH:MM'. Returns matching rows with their log line_no."""
    return T.filter_events(event=event, user=user, ip=ip, start=start, end=end, limit=limit)


@tool
def ip_profile(ip: str) -> dict:
    """Get full activity summary for an IP: failed/accepted counts, usernames tried,
    first and last seen timestamps, and first successful login timestamp."""
    return T.ip_profile(ip)


@tool
def frequency_stats(event: str = 'failed', window: str = '1h', top: int = 5) -> dict:
    """Find busiest time windows for an event ('failed' or 'accepted') to spot bursts."""
    return T.frequency_stats(event=event, window=window, top=top)


@tool
def top_ips(event: str = 'failed', n: int = 5) -> dict:
    """Return top N IPs with the highest count of failed or accepted attempts."""
    return T.top_ips(event=event, n=n)


@tool
def correlate() -> list:
    """Find IPs that had failed logins before eventually succeeding (break-in pattern)."""
    return T.correlate()


@tool
def calculate(expression: str) -> dict:
    """Perform safe arithmetic calculations (ratios, percentages, counts)."""
    return T.calculate(expression)


@tool
def report_draft(findings: list, severity: str, action: str) -> str:
    """Format the final markdown report from verified findings, severity, and action."""
    return T.report_draft(findings, severity, action)


TOOLS = [filter_events, ip_profile, frequency_stats, top_ips, correlate, calculate, report_draft]
MAX_RETRIES = 1


class FlexLLM:
    """
    Custom LLM wrapper with fallback support.
    Tries Groq first (fast and free), and falls back to OpenAI if Groq is down or rate-limited.
    """
    def __init__(self):
        load_dotenv()
        groq_key = os.getenv('GROQ_API_KEY')
        if groq_key:
            self._groq = ChatGroq(model=GROQ_MODEL, temperature=0)
        else:
            self._groq = None
        self._openai = None

    def _init_openai(self):
        # Lazy load ChatOpenAI only when needed
        if self._openai is None:
            openai_key = os.getenv('OPENAI_API_KEY')
            if not openai_key:
                raise RuntimeError('Groq failed and OPENAI_API_KEY is not set in .env')
            from langchain_openai import ChatOpenAI
            self._openai = ChatOpenAI(model=OPENAI_MODEL, temperature=0)
        return self._openai

    def invoke(self, messages, tools=None):
        # 1. Attempt Groq call
        if self._groq is not None:
            try:
                if tools:
                    return self._groq.bind_tools(tools).invoke(messages)
                return self._groq.invoke(messages)
            except Exception as e:
                print(f"[Fallback Warning] Groq failed ({e}), switching to OpenAI...")

        # 2. Fallback to OpenAI
        openai_model = self._init_openai()
        if tools:
            return openai_model.bind_tools(tools).invoke(messages)
        return openai_model.invoke(messages)


def call_with_retry(func):
    """
    Helper function to retry LLM invocations up to 3 times
    if an API rate limit or network glitch occurs.
    """
    for attempt in range(3):
        try:
            return func()
        except Exception as err:
            wait_time = 15 * (attempt + 1)
            print(f"[Retry {attempt + 1}/3] API Error: {err}. Retrying in {wait_time}s...")
            time.sleep(wait_time)
            
    # Final try
    return func()


def initial_state(question):
    """Build the initial empty state dictionary for a new user query."""
    return {
        'question': question,
        'messages': [HumanMessage(content=question)],
        'findings': [],
        'cited_lines': [],
        'evidence': [],
        'verdict': '',
        'verifier_notes': '',
        'retries': 0,
        'report': '',
        'report_data': {}
    }


def build_graph(llm=None):
    """
    Construct and compile the multi-agent LangGraph workflow:
    Investigator -> Tools -> Extract -> Verifier -> Reporter
    """
    model = llm if llm is not None else FlexLLM()

    # Node 1: Investigator Agent
    def investigator_node(state):
        system_msg = ('system', agents.INVESTIGATOR_SYSTEM)
        convo = [system_msg] + state['messages']
        res = call_with_retry(lambda: model.invoke(convo, tools=TOOLS))
        return {'messages': [res]}

    # Node 2: Extract JSON findings from Investigator
    def extract_node(state):
        last_text = state['messages'][-1].content
        parsed = agents.extract_json(last_text) or {}
        
        findings = parsed.get('findings')
        if not findings:
            findings = [last_text.strip()]
            
        line_citations = parsed.get('cited_lines') or []
        cleaned_lines = []
        for item in line_citations:
            if str(item).isdigit():
                cleaned_lines.append(int(item))
                
        return {'findings': findings, 'cited_lines': cleaned_lines}

    # Node 3: Verifier Node
    def verifier_node(state):
        evidence, problems = agents.verify_findings(state['findings'], state['cited_lines'])
        
        # If verification passes
        if not problems:
            return {'evidence': evidence, 'verdict': 'pass', 'verifier_notes': ''}
            
        # If verification fails, prepare retry feedback
        summary_problems = '; '.join(problems)
        print(f"[Verifier Alert] Issues found: {summary_problems}")
        retry_prompt = agents.VERIFIER_RETRY_TEMPLATE.format(problems=summary_problems)
        retry_msg = HumanMessage(content=retry_prompt)
        
        return {
            'evidence': evidence,
            'verdict': 'retry',
            'verifier_notes': summary_problems,
            'retries': state['retries'] + 1,
            'messages': [retry_msg]
        }

    # Node 4: Reporter Agent
    def reporter_node(state):
        if state['evidence']:
            evidence_text = '\n'.join(state['evidence'])
        else:
            evidence_text = '(no raw evidence lines cited)'
            
        uncertainty_note = ''
        if state['verifier_notes']:
            uncertainty_note = f"\nWarning: Verifier noted potential discrepancies: {state['verifier_notes']}"
            
        prompt = (
            f"User Question: {state['question']}\n\n"
            f"Verified Findings:\n"
            + '\n'.join(f"- {f}" for f in state['findings'])
            + f"\n\nCited Evidence Lines:\n{evidence_text}{uncertainty_note}"
        )
        
        response = call_with_retry(lambda: model.invoke([
            ('system', agents.REPORTER_SYSTEM),
            ('human', prompt)
        ]))
        
        parsed_rep = agents.extract_json(response.content)

        # Always force the reply into the report schema, even when the model
        # answered with plain text instead of JSON
        report_data = agents.shape_report(parsed_rep, state['findings'], response.content)
        report_text = T.report_draft(
            [report_data['summary']] + report_data['findings'],
            report_data['severity'],
            report_data['action']
        )

        return {'report': report_text, 'report_data': report_data}

    # Routing logic
    def route_investigator(state):
        last_msg = state['messages'][-1]
        tool_calls = getattr(last_msg, 'tool_calls', None)
        if tool_calls:
            return 'tools'
        return 'extract'

    def route_verifier(state):
        if state['verdict'] == 'pass':
            return 'reporter'
        if state['retries'] <= MAX_RETRIES:
            return 'investigator'
        return 'reporter'

    # Build StateGraph
    graph_builder = StateGraph(LogState)
    graph_builder.add_node('investigator', investigator_node)
    graph_builder.add_node('tools', ToolNode(TOOLS))
    graph_builder.add_node('extract', extract_node)
    graph_builder.add_node('verifier', verifier_node)
    graph_builder.add_node('reporter', reporter_node)

    # Add edges
    graph_builder.add_edge(START, 'investigator')
    graph_builder.add_conditional_edges(
        'investigator',
        route_investigator,
        {'tools': 'tools', 'extract': 'extract'}
    )
    graph_builder.add_edge('tools', 'investigator')
    graph_builder.add_edge('extract', 'verifier')
    graph_builder.add_conditional_edges(
        'verifier',
        route_verifier,
        {'investigator': 'investigator', 'reporter': 'reporter'}
    )
    graph_builder.add_edge('reporter', END)

    return graph_builder.compile()


def answer(question, log_path='data/auth.log', year=2026):
    """Run full investigation workflow and return the completed state."""
    T.DF = load_log(log_path, year=year)
    compiled_app = build_graph()
    return compiled_app.invoke(initial_state(question), config={'recursion_limit': 45})


def run_stream(question, log_path='data/auth.log', year=2026):
    """Stream graph updates step-by-step for the Streamlit interface."""
    T.DF = load_log(log_path, year=year)
    compiled_app = build_graph()
    for chunk in compiled_app.stream(initial_state(question), config={'recursion_limit': 45}, stream_mode='updates'):
        yield from chunk.items()
