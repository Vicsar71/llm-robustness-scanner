"""Common interface for any target model (Adapter pattern).

The whole scanner talks to the target through this minimal interface, without
knowing whether it is Ollama, the Claude API, or something else underneath. To
support a new model you only need to add another Target subclass.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class Target(ABC):
    """A model under test. It only needs to 'take a prompt and answer'."""

    name: str
    model: str

    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Send a prompt to the model and return its response as plain text."""
        raise NotImplementedError
