from app.agent_core.tools import tools
from app.agent_core.chat_state import ChatState
from app.agent_core.prompts import QUERY_ROUTER_PROMPT, GENERATOR_PROMPT
from langchain_core.messages import SystemMessage
from datetime import datetime
import re

def safe_format(template: str, **kwargs) -> str:
    """
    Replace only the placeholders provided in kwargs and leave other {...} intact.
    """
    def repl(m):
        key = m.group(1)
        return str(kwargs[key]) if key in kwargs else m.group(0)
    return re.sub(r"\{([^{}]+)\}", repl, template)

def query_router(state: ChatState):
    """Generate tool call for retrieval or respond."""
    # Format the system prompt with context variables
    system_prompt_content = safe_format(
        QUERY_ROUTER_PROMPT,
        user_id=state['user_id']
    )
    system_message = SystemMessage(content=system_prompt_content)

    conversation_messages = [
        message
        for message in state["messages"]
        if message.type in ("human", "system")
        or (message.type == "ai" and not message.tool_calls)
    ][-5:]
    # print(state["messages"])
    prompt = [system_message] + conversation_messages

    
    input_token_count = state["llm"].get_num_tokens(str(prompt))
    print("Input tokens:", input_token_count)
    if state.get("context_window") and input_token_count > int(state["context_window"]):
        raise Exception(f"Input tokens ({input_token_count}) exceeds context window ({state['context_window']}). Please shorten your message.")

    llm_with_tools = state["llm"].bind_tools(tools)
    response = llm_with_tools.invoke(prompt)
    
    return {"messages": [response]}


def generate(state: ChatState):
    """Generate answer."""
    recent_tool_messages = []
    for message in reversed(state["messages"]):
        if message.type == "tool":
            recent_tool_messages.append(message)
        else:
            break
    tool_messages = recent_tool_messages[::-1]

    docs_content = "\n\n".join(doc.content for doc in tool_messages if doc.name == "retrieve_documents")
    chat_history = "\n\n".join(doc.content for doc in tool_messages if doc.name == "retrieve_chat_history")
    user_memory = "\n\n".join(doc.content for doc in tool_messages if doc.name == "fetch_user_memory")

    # print(docs_content)
    # print(chat_history)
    # print(user_memory)

    # Format the system prompt with context variables
    system_prompt_content = GENERATOR_PROMPT.format(
        current_date=datetime.now().strftime('%d-%m-%Y'),
        user_id=state['user_id'],
        docs_content=docs_content,
        chat_history=chat_history,
        user_memory=user_memory
    )

    # With last 5 messages
    conversation_messages = [
        message
        for message in state["messages"]
        if message.type in ("human", "system")
        or (message.type == "ai" and not message.tool_calls)
    ][-5:]
    # print(conversation_messages)

    prompt = [SystemMessage(system_prompt_content)] + conversation_messages

    input_token_count = state["llm"].get_num_tokens(str(prompt))
    print("Input tokens:", input_token_count)
    if state.get("context_window") and input_token_count > int(state["context_window"]):
        raise Exception(f"Input tokens ({input_token_count}) exceeds context window ({state['context_window']}). Please shorten your message.")
    
    response = state["llm"].invoke(prompt)

    return {"messages": [response]}

