from langchain_core.tools import tool
from app.utils.agent import get_vector_store
from app.api.deps import get_database_service_session
from app.services.crud import DBService
from uuid import UUID

chats_vector_store = get_vector_store("chats")
documents_vector_store = get_vector_store("documents")

@tool(response_format="content_and_artifact")
def retrieve_chat_history(query: str, user_id: str):
    """
    Retrieves semantically relevant chat messages from the user's conversation history.
    Filters results by the current conversation ID to maintain context and relevance.
    Returns formatted output along with the underlying chat document objects.
    """
    print("In retrieve chat history tool")
    retriever = chats_vector_store.as_retriever(
        search_type="similarity", search_kwargs={
            "filter": {"user_id": {"$in": [user_id]}},
            "score_threshold": 0.5
        }
    )
    retrieved_docs = retriever.invoke(query)
    serialized = "\n\n".join(
        (f"Source: {doc.metadata}\nContent: {doc.page_content}")
        for doc in retrieved_docs[:10]
    )
    return serialized, retrieved_docs[:10]



@tool(response_format="content_and_artifact")
def retrieve_documents(query: str):
    """
    Performs a similarity search against user-uploaded documents based on the input query.
    Returns serialized content with metadata and raw document artifacts for contextual display or reasoning.
    """
    print("In retrieve documents tool")
    retriever = documents_vector_store.as_retriever(
        search_type="similarity", search_kwargs={
            "score_threshold": 0.5
        }
    )
    retrieved_docs = retriever.invoke(query)
    serialized = "\n\n".join(
        (f"Source: {doc.metadata}\nContent: {doc.page_content}")
        for doc in retrieved_docs[:10]
    )
    return serialized, retrieved_docs[:10]

@tool(response_format="content")
def fetch_user_memory(user_id: str):
    """
    Fetches stored memory entries associated with the user.
    Returns key-value pairs representing persistent information such as preferences, routines, or prior facts.
    """
    print("In fetch user memory tool")
    # Use the existing session generator pattern
    session_gen = get_database_service_session()
    session = next(session_gen)
    try:
        db = DBService(session)
        memories = db.get_memories_by_user(user_id)
        # for memory in memories:
        #     print(memory.key, memory.value, memory.created_at)
        return "\n".join([
            f"[{memory.created_at.strftime('%d-%m-%Y')}] {memory.key}: {memory.value}"
            for memory in memories
        ])
    except Exception as e:
        print(f"Error fetching user memory: {e}")
        return ""
    finally:
        try:
            next(session_gen)  # This triggers the finally block in get_database_service_session
        except StopIteration:
            pass


@tool(response_format="content")
def store_user_memory(user_id: UUID, key: str, value: str):
    """
    Stores a new memory entry for the user by associating a descriptive key with a specific value.
    Enables the agent to retain important user-provided context for future interactions.
    """
    print("In store user memory tool")
    # Use the existing session generator pattern
    session_gen = get_database_service_session()
    session = next(session_gen)
    try:
        db = DBService(session)
        db.store_memeory(user_id=user_id, key=key, value=value)
        session.commit()
    except Exception as e:
        session.rollback()
        print(f"Error creating user memory: {e}")
    finally:
        try:
            next(session_gen)  # This triggers the finally block in get_database_service_session
        except StopIteration:
            pass

tools = [retrieve_chat_history, retrieve_documents, fetch_user_memory, store_user_memory]

