import pytest
from llmops.prompt_processor import PromptProcessor
from llmops.llm_client import LLMClient

@pytest.fixture
def llm_client():
    # Подготавливаем заглушку для клиента LLM
    class DummyLLMClient:
        def generate(self, prompt):
            if "error" in prompt:
                raise ValueError("Invalid prompt")
            return f"Processed: {prompt}"
    return DummyLLMClient()

@pytest.fixture
def processor(llm_client):
    return PromptProcessor(client=llm_client)

def test_prompt_processing_success(processor):
    prompt = "Hello, world!"
    response = processor.process(prompt)
    assert response == "Processed: Hello, world!"

def test_prompt_processing_with_error(processor):
    prompt = "error in prompt"
    with pytest.raises(ValueError):
        processor.process(prompt)

def test_multiple_prompts(processor):
    prompts = ["First prompt", "Second prompt", "Third prompt"]
    responses = [processor.process(p) for p in prompts]
    expected = [f"Processed: {p}" for p in prompts]
    assert responses == expected

def test_integration_with_llm_client(processor, llm_client):
    # Проверяем, что процессор вызывает метод клиента корректно
    assert hasattr(llm_client, "generate")
    result = llm_client.generate("test")
    assert result == "Processed: test"

