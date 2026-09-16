# Regression fixture: found scanning BerriAI/litellm's 17k-line
# proxy_server.py. A module-level settings-schema dict (no enclosing
# function) with an injection-phrase-shaped description must not be treated
# as MCP tool metadata just because an unrelated MCP listing endpoint exists
# far away in the same file — the module-level context window is capped,
# not "the whole file".
UI_SETTINGS_SCHEMA = {
    "enable_anthropic_prompt_caching": {
        "type": "Boolean",
        "description": (
            "Auto-adds cache_control to the system prompt and trailing turn "
            "for supported Anthropic and Bedrock Claude models."
        ),
    },
}


def _filler_1():
    return 1


def _filler_2():
    return 2


def _filler_3():
    return 3


def _filler_4():
    return 4


def _filler_5():
    return 5


def _filler_6():
    return 6


def _filler_7():
    return 7


def _filler_8():
    return 8


def _filler_9():
    return 9


def _filler_10():
    return 10


# Real MCP tool listing lives far below — outside the settings-dict's
# context window, so it must not retroactively justify the finding above.
def list_mcp_tools():
    return []
