from app.models.database_models import ModelProvider
from langchain_google_genai import ChatGoogleGenerativeAI
# from langchain_openai import ChatOpenAI
# from langchain_anthropic import ChatAnthropic
# from langchain_groq import ChatGroq


def get_model(model_name: str, provider: ModelProvider, temperature: float = 0):
    match provider:
        case ModelProvider.google_genai:
            return ChatGoogleGenerativeAI(model=model_name, temperature=temperature)
        case _:
            raise ValueError(f"Unsupported provider: {provider}")