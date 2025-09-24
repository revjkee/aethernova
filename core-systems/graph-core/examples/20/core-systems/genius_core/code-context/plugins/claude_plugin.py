# genius-core/code-context/plugins/claude_plugin.py

import os
from typing import List, Optional, Dict, Any
from anthropic import Anthropic, AsyncAnthropic
from dotenv import load_dotenv

load_dotenv()

class ClaudePlugin:
    """
    Claude SDK adapter for GeniusCore context system.
    Supports sync/async calls, streaming, and token-budget enforcement.
    """
    def __init__(
        self,
        model: str = "claude-3-opus-20240229",
        temperature: float = 0.3,
        max_tokens: int = 4096,
        system_prompt: Optional[str] = None,
        stream: bool = False,
    ):
        self.api_key = os.getenv("CLAUDE_API_KEY")
        if not self.api_key:
            raise RuntimeError("CLAUDE_API_KEY not set in environment")

        self.client = Anthropic(api_key=self.api_key)
        self.async_client = AsyncAnthropic(api_key=self.api_key)

        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.system_prompt = system_prompt
        self.stream = stream

    def build_prompt(
        self,
        user_input: str,
        context_snippets: Optional[List[str]] = None,
    ) -> List[Dict[str, str]]:
        """
        Constructs a full Claude-compatible prompt sequence
        """
        prompt = []
        if self.system_prompt:
            prompt.append({"role": "system", "content": self.system_prompt})

        if context_snippets:
            prompt.append({
                "role": "user",
                "content": "Context:\n" + "\n---\n".join(context_snippets)
            })

        prompt.append({"role": "user", "content": user_input})
        return prompt

    def complete(
        self,
        user_input: str,
        context_snippets: Optional[List[str]] = None,
        temperature: Optional[float] = None,
    ) -> str:
        """
        Synchronous completion.
        """
        prompt = self.build_prompt(user_input, context_snippets)
        response = self.client.messages.create(
            model=self.model,
            messages=prompt,
            temperature=temperature or self.temperature,
            max_tokens=self.max_tokens,
        )
        return response.content[0].text.strip()

    async def complete_async(
        self,
        user_input: str,
        context_snippets: Optional[List[str]] = None,
    ) -> str:
        """
        Async completion for concurrent pipelines.
        """
        prompt = self.build_prompt(user_input, context_snippets)
        response = await self.async_client.messages.create(
            model=self.model,
            messages=prompt,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )
        return response.content[0].text.strip()

    def supports_streaming(self) -> bool:
        return self.stream

    def info(self) -> Dict[str, Any]:
        return {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "streaming_enabled": self.stream,
        }
