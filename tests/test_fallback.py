import pytest

from logguard import graph


class DeadGroq:
    def invoke(self, messages, tools=None):
        raise ConnectionError('groq down')


class FakeOpenAI:
    def bind_tools(self, tools):
        return self

    def invoke(self, messages, tools=None):
        return 'ok'


def test_fallback_switches_to_openai():
    flex = graph.FlexLLM()
    flex._groq = DeadGroq()
    flex._openai = FakeOpenAI()
    assert flex.invoke('hi') == 'ok'


def test_fallback_with_tools():
    flex = graph.FlexLLM()
    flex._groq = DeadGroq()
    flex._openai = FakeOpenAI()
    assert flex.invoke('hi', tools=['x']) == 'ok'


def test_groq_still_working_is_used():
    flex = graph.FlexLLM()
    flex._groq = FakeOpenAI()
    assert flex.invoke('hi') == 'ok'


def test_no_openai_key_gives_clear_error(monkeypatch):
    flex = graph.FlexLLM()
    flex._groq = DeadGroq()
    flex._openai = None
    monkeypatch.delenv('OPENAI_API_KEY', raising=False)
    with pytest.raises(RuntimeError, match='OPENAI_API_KEY'):
        flex.invoke('hi')
