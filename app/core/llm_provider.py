"""Provider abstraction.

The gate (access control + sensitivity) runs upstream of this layer, so the
provider choice has no bearing on safety. Swapping mock ↔ Anthropic must not
change what reaches the model.
"""
from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import Optional


class LLMProvider(ABC):
    name: str

    @abstractmethod
    def chat(self, system: str, user: str) -> str:
        ...


class MockProvider(LLMProvider):
    """Deterministic echo provider.

    The response includes the user-message body verbatim. This is what makes
    leakage observable in tests: if confidential content reaches the prompt,
    it surfaces in the response, and the adversarial tests can assert on it.
    A real LLM would paraphrase, obscuring the leak without fixing it.
    """

    name = "mock"

    def chat(self, system: str, user: str) -> str:
        return f"[mock-llm] system={system!r} :: user={user}"


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, api_key: str, model: str) -> None:
        try:
            import anthropic
        except ImportError as e:
            raise RuntimeError(
                "anthropic package not installed. Install with: pip install -e .[anthropic]"
            ) from e
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model

    def chat(self, system: str, user: str) -> str:
        msg = self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        parts = [b.text for b in msg.content if getattr(b, "type", None) == "text"]
        return "".join(parts)


def get_provider(override: Optional[str] = None) -> LLMProvider:
    choice = (override or os.getenv("CONTEXTGATE_LLM_PROVIDER", "mock")).lower()
    if choice == "mock":
        return MockProvider()
    if choice == "anthropic":
        key = os.getenv("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError(
                "CONTEXTGATE_LLM_PROVIDER=anthropic but ANTHROPIC_API_KEY is unset."
            )
        model = os.getenv("CONTEXTGATE_ANTHROPIC_MODEL", "claude-opus-4-7")
        return AnthropicProvider(api_key=key, model=model)
    raise ValueError(f"Unknown provider: {choice!r}")
