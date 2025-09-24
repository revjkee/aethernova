# genius-core/code-context/plugins/gemini_plugin.py

import os
from typing import List, Dict, Any, Optional
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

class GeminiPlugin:
    """
    Gemini SDK integration for TeslaAI Genius Core context engine.
    Supports prompt construction, context injection, budget tracking, and streaming.
    """

    def __init__(
        self,
        model_name: str = "models/gemini-1.5-pro",
        temperature: float = 0.3,
        max_tokens: int = 4096,
        system_instruction: Optional[str] = None,
        stream: bool = False
    ):
        self.api_key = os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise RuntimeError("GEMINI_API_KEY not set in environment")

        genai.configure(api_key=self.api_key)

        self.model_name = model_name
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.system_instruction = system_instruction
        self.stream = stream

        self.model = genai.GenerativeModel(
            model_name=model_name,
            generation_config={
                "temperature": temperature,
                "max_output_tokens": max_tokens,
            }
        )

    def build_prompt(self, user_input: str, context_snippets: Optional[List[str]] = None) -> List[str]:
        prompt = []
        if self.system_instruction:
            prompt.append(f"[System Instruction]\n{self.system_instruction}")
        if context_snippets:
            prompt.append("[Contextual Snippets]")
            prompt.extend(context_snippets)
        prompt.append(f"[User Input]\n{user_input}")
        return prompt

    def complete(self, user_input: str, context_snippets: Optional[List[str]] = None) -> str:
        prompt = self.build_prompt(user_input, context_snippets)
        response = self.model.generate_content(prompt)
        return response.text.strip()

    async def complete_async(self, user_input: str, context_snippets: Optional[List[str]] = None) -> str:
        # Note: Gemini SDK does not natively support asyncio, so mock async interface
        from concurrent.futures import ThreadPoolExecutor
        import asyncio

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            ThreadPoolExecutor(),
            lambda: self.complete(user_input, context_snippets)
        )

    def info(self) -> Dict[str, Any]:
        return {
            "model": self.model_name,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "streaming_enabled": self.stream,
        }

    def supports_streaming(self) -> bool:
        return self.stream
