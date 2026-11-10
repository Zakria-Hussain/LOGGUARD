# Usage: python -m logguard.ask "Did any attacker eventually get in?"

import sys
from logguard import graph


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m logguard.ask \"<your question here>\"")
        sys.exit(1)
        
    query = ' '.join(sys.argv[1:])
    print(f"Investigating query: \"{query}\"...")
    
    final_state = graph.answer(query)

    print("\n" + "=" * 30 + " INVESTIGATION TRACE " + "=" * 30)
    for msg in final_state['messages']:
        msg_type = type(msg).__name__.replace('Message', '')
        content = (str(msg.content) or '').replace('\n', ' ')[:160]
        tool_calls = getattr(msg, 'tool_calls', None)
        
        if tool_calls:
            for call in tool_calls:
                print(f"[{msg_type}] calls tool -> {call['name']}({call['args']})")
        elif content:
            print(f"[{msg_type}] {content}")

    print("\n" + "=" * 30 + " VERIFIER RESULT " + "=" * 30)
    print(f"Status: {final_state['verdict'].upper()} (Retries used: {final_state['retries']})")
    for ev in final_state['evidence']:
        print(f"  {ev}")

    print("\n" + "=" * 30 + " INCIDENT REPORT " + "=" * 30)
    print(final_state['report'])
    print("=" * 77 + "\n")


if __name__ == '__main__':
    main()
