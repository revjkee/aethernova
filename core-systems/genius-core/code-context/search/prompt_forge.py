# genius-core/code-context/search/prompt_forge.py

from typing import Dict, Optional, List
import textwrap


MODEL_TEMPLATES = {
    "claude": {
        "prefix": "You are a world-class coding assistant. Analyze the following code and answer the user’s intent:",
        "suffix": "Return your answer in structured markdown format."
    },
    "gpt": {
        "prefix": "You are an expert code engineer. Process this request:",
        "suffix": "Respond using bullet points or code blocks where needed."
    },
    "gemini": {
        "prefix": "You are Google's Gemini AI. Interpret and complete the following instruction with code if applicable:",
        "suffix": "Make sure your response is clean and minimal."
    },
    "llama": {
        "prefix": "Given the code snippet below, perform the task requested:",
        "suffix": "Output should be strictly the final answer."
    }
}


def clean_code_snippet(code: str) -> str:
    return textwrap.dedent(code.strip())


def build_prompt(
    code_snippet: str,
    task_description: str,
    model: str = "claude",
    ast_summary: Optional[str] = None,
    symbol_info: Optional[List[str]] = None,
    dependency_trace: Optional[List[str]] = None,
    language: str = "python"
) -> str:
    """
    Генерирует адаптированный промпт для заданной модели
    """

    tmpl = MODEL_TEMPLATES.get(model.lower())
    if not tmpl:
        raise ValueError(f"Unsupported model: {model}")

    sections = [
        f"{tmpl['prefix']}",
        f"\n## Task:\n{task_description.strip()}",
        f"\n## Language:\n{language}",
        f"\n## Code Snippet:\n```{language}\n{clean_code_snippet(code_snippet)}\n```"
    ]

    if ast_summary:
        sections.append(f"\n## AST Summary:\n{ast_summary.strip()}")

    if symbol_info:
        sections.append(f"\n## Symbol Relations:\n" + "\n".join(symbol_info))

    if dependency_trace:
        sections.append(f"\n## Dependencies:\n" + "\n".join(dependency_trace))

    sections.append(f"\n{tmpl['suffix']}")
    return "\n".join(sections)
