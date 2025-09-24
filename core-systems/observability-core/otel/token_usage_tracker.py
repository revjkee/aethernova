# observability/dashboards/otel/token_usage_tracker.py

from opentelemetry import trace
from opentelemetry.metrics import get_meter_provider

meter = get_meter_provider().get_meter("teslaai.token_tracker", "1.0.0")
tracer = trace.get_tracer("teslaai.token_tracer")

# Метрики
prompt_tokens_counter = meter.create_counter(
    name="llm_prompt_tokens_total",
    description="Количество токенов в prompt для LLM",
    unit="tokens"
)

completion_tokens_counter = meter.create_counter(
    name="llm_completion_tokens_total",
    description="Количество токенов в completion для LLM",
    unit="tokens"
)

total_tokens_counter = meter.create_counter(
    name="llm_total_tokens_used",
    description="Общее количество токенов, использованных LLM",
    unit="tokens"
)


def track_tokens(prompt_tokens: int, completion_tokens: int, user_id: str = "anonymous", model: str = "unknown"):
    """
    Отслеживает использование токенов на уровне запроса и отправляет в OpenTelemetry
    :param prompt_tokens: токены в prompt-запросе
    :param completion_tokens: токены в ответе
    :param user_id: идентификатор пользователя
    :param model: название модели (например, gpt-4o)
    """
    total = prompt_tokens + completion_tokens

    attrs = {
        "user_id": user_id,
        "model": model
    }

    prompt_tokens_counter.add(prompt_tokens, attributes=attrs)
    completion_tokens_counter.add(completion_tokens, attributes=attrs)
    total_tokens_counter.add(total, attributes=attrs)

    with tracer.start_as_current_span("llm.token.usage") as span:
        span.set_attribute("user_id", user_id)
        span.set_attribute("model", model)
        span.set_attribute("prompt_tokens", prompt_tokens)
        span.set_attribute("completion_tokens", completion_tokens)
        span.set_attribute("total_tokens", total)
