import streamlit as st
from dotenv import load_dotenv

from logguard import graph
from logguard.parser import load_log

# Load environment variables (.env file)
load_dotenv()

# Dictionary of available log datasets
LOG_FILES = {
    'Synthetic Dataset (data/auth.log)': ('data/auth.log', 2026),
    'Real Loghub OpenSSH (data/loghub_openssh.log)': ('data/loghub_openssh.log', 2015),
}

# Map each severity level to a colored Streamlit alert box
SEVERITY_STYLE = {
    'Critical': st.error,   # red
    'High': st.warning,     # orange
    'Medium': st.info,      # blue
    'Low': st.success,      # green
    'Unknown': st.info,
}

def show_report(report_data):
    """Render the final incident report as a structured card instead of raw markdown."""
    severity = report_data.get('severity', 'Unknown')
    SEVERITY_STYLE.get(severity, st.info)(f'**Severity: {severity}**')

    st.subheader('Summary')
    st.markdown(report_data.get('summary', ''))

    st.subheader('Findings')
    for f in report_data.get('findings', []):
        st.markdown(f'- {f}')

    st.subheader('Recommended action')
    st.markdown(report_data.get('action', 'none'))

st.set_page_config(page_title='LogGuard - AI Security Log Analyst', page_icon='🛡️')
st.title('🛡️ LogGuard')
st.caption('Multi-Agent Security Log Investigation System (Investigator -> Verifier -> Reporter)')

# Sidebar controls
st.sidebar.header('LogGuard Settings')
selected_log_name = st.sidebar.selectbox('Choose Log File', list(LOG_FILES.keys()))
log_path, log_year = LOG_FILES[selected_log_name]

# Check if log file is parsed successfully
try:
    log_df = load_log(log_path, log_year)
    total_events = len(log_df)
    st.sidebar.success(f'Loaded {total_events} events from log.')
except Exception as err:
    st.sidebar.warning(f'Could not load {log_path}: {err}')

st.sidebar.divider()
st.sidebar.subheader('Sample Questions:')
st.sidebar.markdown("""
- *Did any attacker eventually get in?*
- *Was there a brute force burst tonight?*
- *Did the user alice do anything suspicious?*
- *Which IP failed the most logins?*
""")

st.sidebar.divider()
st.sidebar.info('**Models:** Primary: Groq (gpt-oss-20b) | Fallback: OpenAI (gpt-5-mini)')

# Initialize chat history in session state
if 'messages' not in st.session_state:
    st.session_state.messages = []

# Display conversation messages from history
for chat_msg in st.session_state.messages:
    with st.chat_message(chat_msg['role']):
        if chat_msg['role'] == 'assistant' and chat_msg.get('report'):
            show_report(chat_msg['report'])
        else:
            st.markdown(chat_msg['content'])

# Chat input prompt
user_query = st.chat_input('Ask a question about the server auth logs...')

if user_query:
    # Append user question to history and display
    st.session_state.messages.append({'role': 'user', 'content': user_query})
    with st.chat_message('user'):
        st.markdown(user_query)

    # Process answer with streaming agent updates
    with st.chat_message('assistant'):
        final_report = ''
        final_data = {}
        try:
            with st.spinner('Agents investigating the logs...'):
                for agent_node, state_update in graph.run_stream(user_query, log_path, log_year):
                    
                    # 1. Investigator tool calls
                    if agent_node == 'investigator':
                        tool_calls = getattr(state_update['messages'][-1], 'tool_calls', None) or []
                        for call in tool_calls:
                            with st.expander(f"🔎 Investigator calling tool: `{call['name']}`"):
                                st.write("**Arguments:**", call['args'])
                                
                    # 2. Tool execution results
                    elif agent_node == 'tools':
                        tool_msg = state_update['messages'][-1]
                        tool_name = getattr(tool_msg, 'name', 'tool')
                        with st.expander(f"⚙️ Tool result (`{tool_name}`):"):
                            st.text(str(tool_msg.content)[:600])
                            
                    # 3. Investigator extracted findings
                    elif agent_node == 'extract':
                        findings = state_update.get('findings', [])
                        with st.expander(f"📝 Preliminary Findings ({len(findings)})"):
                            for f in findings:
                                st.markdown(f"- {f}")
                                
                    # 4. Verifier check
                    elif agent_node == 'verifier':
                        verdict = state_update.get('verdict', 'unknown')
                        is_pass = (verdict == 'pass')
                        with st.expander(f"⚖️ Verifier Result: {'PASSED' if is_pass else 'RETRYING'}", expanded=not is_pass):
                            if is_pass:
                                st.write("All cited evidence lines verified against the log.")
                            else:
                                st.warning(f"Verification issues: {state_update.get('verifier_notes')}")
                            for ev in state_update.get('evidence', []):
                                st.code(ev)
                                
                    # 5. Reporter final incident report
                    elif agent_node == 'reporter':
                        final_report = state_update.get('report', '')
                        final_data = state_update.get('report_data', {})

            # Display final report in chat
            if final_data:
                show_report(final_data)
            else:
                st.markdown(final_report)

        except Exception as e:
            st.error(f"Error during agent execution: {e}")
            final_report = f"(Investigation failed with error: {e})"

    # Save assistant report to session history
    st.session_state.messages.append({'role': 'assistant', 'content': final_report, 'report': final_data})
