# agent_rl/copilot_adapter.py

import os
import time
import logging
import uuid
from typing import Any, Dict, Optional, Union

import openai
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception_type
from agent_rl.utils import secure_logger, anomaly_detector


class LLMResponseException(Exception):
    pass


class CopilotAdapter:
    """
    Adapter for communicating with a Large Language Model (LLM), providing:
    - trade explanation generation
    - market context analysis
    - LLM-guided action adjustment
    - threat monitoring on LLM input/output
    - result caching
    """

    def __init__(self,
                 api_key: Optional[str] = None,
                 model: str = "gpt-4",
                 temperature: float = 0.3,
                 log_path: str = "/var/log/teslaai/copilot_adapter.log") -> None:
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = model
        self.temperature = temperature
        self.cache: Dict[str, str] = {}
        self.logger = secure_logger.get_logger("copilot", log_path)

        openai.api_key = self.api_key
        self.request_id = str(uuid.uuid4())[:8]

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10),
        stop=stop_after_attempt(3),
        retry=retry_if_exception_type(Exception),
        reraise=True
    )
    def _query_llm(self, prompt: str) -> str:
        self.logger.info(f"[{self.request_id}] Prompt sent to LLM: {prompt[:250]}")
        if prompt in self.cache:
            return self.cache[prompt]

        try:
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=self.temperature,
                max_tokens=512,
            )
            output = response.choices[0].message.content.strip()

            if anomaly_detector.detect(output):
                self.logger.warning(f"[{self.request_id}] Anomalous LLM output detected")
                raise LLMResponseException("LLM returned unsafe or suspicious output")

            self.cache[prompt] = output
            self.logger.info(f"[{self.request_id}] LLM response received")
            return output

        except Exception as e:
            self.logger.exception(f"[{self.request_id}] Error during LLM call: {str(e)}")
            raise

    def explain_trade_signal(self, signal: Dict[str, Any]) -> str:
        prompt = (
            "Explain the reasoning behind the following trade signal using concise financial logic:\n"
            f"{signal}"
        )
        return self._query_llm(prompt)

    def generate_market_analysis(self, symbol: str, timeframe: str = "1d") -> str:
        prompt = (
            f"Provide a market analysis for symbol '{symbol}' using latest macro trends, "
            f"technical indicators (RSI, EMA), and sentiment. Timeframe: {timeframe}."
        )
        return self._query_llm(prompt)

    def adjust_action(self, observation: Dict[str, Any], action: str) -> str:
        prompt = (
            "Given this market observation, advise a trading action:\n"
            f"{observation}\n"
            f"Initial action proposed: {action}\n"
            "Respond only with: 'buy', 'sell' or 'hold'"
        )
        try:
            decision = self._query_llm(prompt).lower()
            if decision in ["buy", "sell", "hold"]:
                return decision
            return action
        except LLMResponseException:
            return action  # fallback on original decision


# Optional usage
if __name__ == "__main__":
    adapter = CopilotAdapter()
    signal = {"symbol": "ETH", "action": "buy", "confidence": 0.93}
    print(adapter.explain_trade_signal(signal))
