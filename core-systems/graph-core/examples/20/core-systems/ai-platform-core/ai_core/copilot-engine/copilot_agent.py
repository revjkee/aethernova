import os
import logging
import inspect
import traceback
from typing import Any, Dict, Optional, List

from llmops.tuning.model_api import call_llm
from llmops.eval.code_validator import validate_code_syntax
from genius-core/symbolic-reasoning/logical_binder import extract_code_goals
from genius-core/meta-awareness/system_consistency_checker import check_architecture_consistency

# === Copilot Agent v3.2 (TeslaAI) ===
# Agents: CodeSuggester, Refactorer, Explainer, TestGenerator, PromptRewriter,
# ContextIntegrator, SafetyChecker, TraceAnalyzer, GoalAligner, CopilotCache,
# TokenLimiter, SchemaFormatter, ErrorResolver, ChainComposer, SyntaxHighlighter,
# ArchitectureAwareAgent, MutationInjector, EvalReactor, EditorProtocolBinder, IDEBridge
# MetaGenerals: Architectus, Evolver, Guardian

logger = logging.getLogger("copilot_agent")
logger.setLevel(logging.INFO)


class CopilotAgent:
    def __init__(self, llm_model: str = "gpt-4", max_tokens: int = 2048):
        self.llm_model = llm_model
        self.max_tokens = max_tokens
        self.memory_context: List[str] = []
        self.last_code: Optional[str] = None
        self.last_traceback: Optional[str] = None

    def suggest_completion(self, partial_code: str, context: Optional[str] = None) -> str:
        prompt = self._build_prompt(partial_code, context)
        logger.info("Requesting LLM completion...")
        response = call_llm(prompt=prompt, model=self.llm_model, max_tokens=self.max_tokens)
        self.memory_context.append(partial_code)
        self.last_code = response.strip()
        return self.last_code

    def explain_code(self, code_snippet: str) -> str:
        prompt = f"Explain the following code in plain language:\n\n{code_snippet}"
        logger.info("Requesting explanation from LLM...")
        return call_llm(prompt=prompt, model=self.llm_model, max_tokens=1024)

    def generate_tests(self, function_code: str) -> str:
        prompt = f"Write PyTest-compatible unit tests for this function:\n\n{function_code}"
        logger.info("Generating test cases...")
        return call_llm(prompt=prompt, model=self.llm_model, max_tokens=self.max_tokens)

    def refactor_code(self, original_code: str, goal: Optional[str] = None) -> str:
        refactor_goal = goal or "Improve readability, modularity, and performance."
        prompt = f"Refactor the following code with the goal: {refactor_goal}\n\n{original_code}"
        logger.info("Refactoring via LLM...")
        return call_llm(prompt=prompt, model=self.llm_model, max_tokens=self.max_tokens)

    def analyze_exception(self, error_trace: str) -> str:
        self.last_traceback = error_trace
        prompt = f"Analyze this Python traceback and explain what caused the error:\n\n{error_trace}"
        logger.info("Analyzing traceback...")
        return call_llm(prompt=prompt, model=self.llm_model, max_tokens=1024)

    def self_validate(self) -> Dict[str, Any]:
        """Проверка на архитектурную согласованность, синтаксис и корректность"""
        logger.info("Running self-validation...")
        results = {
            "syntax_valid": validate_code_syntax(self.last_code or ""),
            "architecture_check": check_architecture_consistency(self.last_code or ""),
            "goals_matched": extract_code_goals(self.last_code or "")
        }
        return results

    def _build_prompt(self, code: str, context: Optional[str]) -> str:
        base = f"You are a world-class coding copilot. Complete the following Python code:"
        if context:
            base += f"\n\nContext:\n{context}"
        base += f"\n\nCode:\n{code}"
        return base

    def inject_mutation(self, original_code: str, mutation_type: str = "performance") -> str:
        prompt = (
            f"Inject a {mutation_type}-oriented change into the following code, "
            f"while preserving its logic:\n\n{original_code}"
        )
        logger.info(f"Injecting mutation type: {mutation_type}")
        return call_llm(prompt=prompt, model=self.llm_model, max_tokens=self.max_tokens)

    def summarize_diff(self, old_code: str, new_code: str) -> str:
        prompt = (
            f"Compare the following two versions of code and summarize what changed:\n\n"
            f"OLD VERSION:\n{old_code}\n\nNEW VERSION:\n{new_code}"
        )
        logger.info("Summarizing code diff...")
        return call_llm(prompt=prompt, model=self.llm_model, max_tokens=1024)
