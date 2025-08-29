"""
LLM client factory - just creates and returns the correct LLM client
based on configuration. No prompt logic here.
"""

from typing import Any

from langchain_anthropic import ChatAnthropic
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_openai import ChatOpenAI


def get_llm_client(config_manager: Any):
    """Return an LLM client based on configuration."""
    try:
        provider = config_manager.get("llm.provider")
        model = config_manager.get("llm.model")
        temperature = config_manager.get("llm.temperature", 0.0)
        api_key = config_manager.get("llm.api_key")

        if provider == "openai":
            return ChatOpenAI(model=model, temperature=temperature, api_key=api_key)
        elif provider == "anthropic":
            return ChatAnthropic(model=model, temperature=temperature, api_key=api_key)
        elif provider == "gemini":
            return ChatGoogleGenerativeAI(
                model=model, temperature=temperature, api_key=api_key
            )
        else:
            raise ValueError(f"Unsupported LLM provider: {provider}")
    except Exception as e:
        raise ValueError(f"Failed to create LLM client: {e}")
