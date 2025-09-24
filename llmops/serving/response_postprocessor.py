# llmops/serving/response_postprocessor.py

from typing import Dict, Any, Optional
import re
import html

class ResponsePostprocessor:
    """
    Класс для постобработки ответов от LLM.
    Обеспечивает очистку, форматирование и стандартизацию результата перед отдачей клиенту.
    """

    def __init__(self, 
                 unescape_html: bool = True,
                 trim_whitespace: bool = True,
                 remove_control_chars: bool = True,
                 max_length: Optional[int] = None):
        self.unescape_html = unescape_html
        self.trim_whitespace = trim_whitespace
        self.remove_control_chars = remove_control_chars
        self.max_length = max_length

        # Регулярное выражение для удаления управляющих символов кроме \n и \t
        self.control_chars_pattern = re.compile(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]')

    def postprocess_text(self, text: str) -> str:
        if self.unescape_html:
            text = html.unescape(text)

        if self.remove_control_chars:
            text = self.control_chars_pattern.sub('', text)

        if self.trim_whitespace:
            text = text.strip()

        if self.max_length is not None and len(text) > self.max_length:
            text = text[:self.max_length]

        return text

    def postprocess_response(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Обрабатывает ключи с текстом в словаре ответа.
        Ожидается, что ключи с текстом — 'response', 'output', 'text'.
        """
        processed = response_data.copy()

        for key in ['response', 'output', 'text']:
            if key in processed and isinstance(processed[key], str):
                processed[key] = self.postprocess_text(processed[key])

        return processed
