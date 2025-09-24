import logging
from typing import Optional, Dict, Any
from hr_ai.translation.providers import TranslationRouter
from hr_ai.localization.terminology_adapter import apply_corporate_terms
from hr_ai.localization.fallback_engine import resolve_fallback
from hr_ai.security.input_validator import sanitize_text
from hr_ai.config.settings import DEFAULT_LANGUAGE, SUPPORTED_LANGUAGES

logger = logging.getLogger("LanguageLocalizer")
logger.setLevel(logging.INFO)

class LanguageLocalizer:
    def __init__(self, default_lang: str = DEFAULT_LANGUAGE):
        self.default_lang = default_lang
        self.translator = TranslationRouter()

    def localize_text(
        self,
        text: str,
        source_lang: Optional[str] = None,
        target_lang: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        if not text.strip():
            logger.warning("Empty text provided for localization")
            return ""

        clean_text = sanitize_text(text)
        target_lang = target_lang or self.default_lang

        if target_lang not in SUPPORTED_LANGUAGES:
            logger.warning(f"Unsupported target language '{target_lang}', using fallback")
            target_lang = resolve_fallback(target_lang)

        try:
            translated = self.translator.translate(
                text=clean_text,
                source_lang=source_lang,
                target_lang=target_lang
            )
        except Exception as e:
            logger.error(f"Translation error: {e}")
            return clean_text

        adapted = apply_corporate_terms(translated, context or {}, language=target_lang)
        return adapted

    def batch_localize(
        self,
        entries: Dict[str, str],
        target_lang: str,
        source_lang: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, str]:
        localized = {}
        for key, value in entries.items():
            localized[key] = self.localize_text(
                text=value,
                source_lang=source_lang,
                target_lang=target_lang,
                context=context
            )
        return localized
