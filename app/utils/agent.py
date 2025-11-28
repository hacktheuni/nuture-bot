import os
from app.core.config import settings
from langchain_postgres import PGVector
from langchain_google_genai import GoogleGenerativeAIEmbeddings


os.environ["GOOGLE_API_KEY"] = settings.GOOGLE_API_KEY

# --- Initialize Embeddings ---
embeddings = GoogleGenerativeAIEmbeddings(
    model="gemini-embedding-001"
)

# --- Vector Store Factory ---
def get_vector_store(collection_name: str) -> PGVector:
    """
    Return a PGVector vector store instance bound to a specific collection.
    Works with Supabase (PGVector extension enabled) or any Postgres setup.
    """
    return PGVector(
        embeddings=embeddings,
        collection_name=collection_name,
        connection=settings.SYNC_CONNECTION_STRING,
        use_jsonb=True,
    )