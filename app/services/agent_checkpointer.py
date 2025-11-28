from typing import Optional

from app.core.config import settings
from app.core.db import engine

from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from contextlib import asynccontextmanager
from sqlalchemy import text

# Global async checkpointer instance
_async_checkpointer: Optional[AsyncPostgresSaver] = None

@asynccontextmanager
async def lifespan_checkpointer(app):
    """
    Lifespan manager for PostgresSaver checkpointer.
    Make sure to pass this as the 'lifespan' argument when creating your FastAPI app:
        app = FastAPI(lifespan=lifespan_checkpointer)
    """
    global _async_checkpointer
    try:
        async with AsyncPostgresSaver.from_conn_string(settings.SYNC_CONNECTION_STRING) as checkpointer:
            await checkpointer.setup()
            _async_checkpointer = checkpointer
            yield
    except Exception as e:
        _async_checkpointer = None
        raise
    finally:
        _async_checkpointer = None

def get_async_checkpointer() -> AsyncPostgresSaver:
    """Get the global async checkpointer instance."""
    if _async_checkpointer is None:
        raise RuntimeError("Async checkpointer not initialized. Make sure the app lifespan is properly set up.")
    return _async_checkpointer


def clear_thread_checkpoints(thread_id: str) -> None:
    try:
        with engine.begin() as conn:
            # Delete dependent rows first (FKs), then main checkpoints
            conn.execute(text("""
                DELETE FROM checkpoint_writes WHERE thread_id = :thread_id
            """), {"thread_id": thread_id})

            conn.execute(text("""
                DELETE FROM checkpoint_blobs WHERE thread_id = :thread_id
            """), {"thread_id": thread_id})

            conn.execute(text("""
                DELETE FROM checkpoints WHERE thread_id = :thread_id
            """), {"thread_id": thread_id})
    except Exception:
        pass