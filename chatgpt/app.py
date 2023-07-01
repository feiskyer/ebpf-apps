#!/usr/bin/env python3
import os

import openai
from chromadb.config import Settings
from langchain.chains import RetrievalQA
from langchain.chat_models import ChatOpenAI
from langchain.document_loaders import DirectoryLoader, TextLoader
from langchain.embeddings import OpenAIEmbeddings
from langchain.text_splitter import CharacterTextSplitter
from langchain.vectorstores import Chroma

# OpenAI Configuration
default_model = 'gpt-4'
if os.getenv("OPENAI_API_TYPE") == "azure" or (os.getenv("OPENAI_API_BASE") is not None and "azure" in os.getenv("OPENAI_API_BASE")):
    openai.api_type = "azure"
    openai.api_base = os.getenv("OPENAI_API_BASE")
    openai.api_version = "2023-05-15"
    openai.api_key = os.getenv("OPENAI_API_KEY")
    llm = ChatOpenAI(model_name=default_model,
                     temperature=0,
                     model_kwargs={"engine": default_model.replace('.', '')})
    embeddings = OpenAIEmbeddings(
        deployment="text-embedding-ada-002",
        model="text-embedding-ada-002",
        openai_api_type=os.getenv("OPENAI_API_TYPE"),
        openai_api_base=os.getenv("OPENAI_API_BASE"),
        openai_api_version="2023-05-15",
        openai_api_key=os.getenv("OPENAI_API_KEY"),
        chunk_size=1  # Only 1 is allowed for Azure OpenAI
    )
else:
    openai.api_key = os.getenv("OPENAI_API_KEY")
    openai.api_base = os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1")
    embeddings = OpenAIEmbeddings(
        model="text-embedding-ada-002",
        openai_api_key=os.getenv("OPENAI_API_KEY"),
    )
    llm = ChatOpenAI(model=default_model,
                     temperature=0)


def load_store():
    '''Load data and embedding.'''
    documents = DirectoryLoader("./doc/",
                                glob="**/*.md",
                                recursive=True,
                                show_progress=True,
                                silent_errors=True,
                                use_multithreading=True,
                                loader_cls=TextLoader,
                                ).load()
    text_splitter = CharacterTextSplitter(chunk_size=4096, separator="\n")
    docs = []
    for d in documents:
        splits = text_splitter.split_text(d.page_content)
        docs.extend(splits)

    chroma_store = Chroma.from_texts(
        docs, embeddings, persist_directory="./store",
        client_settings=Settings(anonymized_telemetry=False))
    return chroma_store


# Initialize store and chain
print('Embedding documents...')
store = load_store()
chain = RetrievalQA.from_chain_type(
    llm=llm, chain_type="refine", retriever=store.as_retriever())

# Run the chain
print('Running chain...')
msg = '作为一名 Linux 内核和 eBPF 的专家，你的任务是开发一个 bpftrace 程序，跟踪系统中进程的系统调用数量。'
print(chain.run(msg))
