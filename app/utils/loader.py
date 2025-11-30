from langchain_community.document_loaders.csv_loader import CSVLoader
from langchain_community.document_loaders import PyPDFLoader
from langchain_community.document_loaders import Docx2txtLoader
from langchain_community.document_loaders import TextLoader

def load_file(file_path: str):
    if file_path.endswith('.csv'):
        docs = CSVLoader(file_path).load()
        return docs
    elif file_path.endswith('.pdf'):
        docs = PyPDFLoader(file_path).load()
        return docs
    elif file_path.endswith('.docx'):
        docs = Docx2txtLoader(file_path).load()
        return docs
    elif file_path.endswith('.txt'):
        docs = TextLoader(file_path).load()
        return docs
    else:
        raise ValueError(f"Unsupported file type: {file_path}")