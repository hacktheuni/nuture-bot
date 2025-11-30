from langgraph.graph import StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt import ToolNode, tools_condition
from app.services.agent_checkpointer import get_async_checkpointer
from langgraph.graph import START, END
from app.agent_core.nodes import query_router, generate
from app.agent_core.tools import tools
from app.agent_core.chat_state import ChatState

def build_graph():
    graph_builder = StateGraph(ChatState) 
    graph_builder.add_node("query_router", query_router)
    graph_builder.add_node("tools", ToolNode(tools))
    graph_builder.add_node("generate", generate)

    graph_builder.add_edge(START, "query_router")
    graph_builder.add_conditional_edges(
        "query_router",
        tools_condition,
        {"__end__": END, "tools": "tools"},
    )
    graph_builder.add_edge("tools", "generate")
    graph_builder.add_edge("generate", END)

    return graph_builder.compile(checkpointer=get_async_checkpointer())