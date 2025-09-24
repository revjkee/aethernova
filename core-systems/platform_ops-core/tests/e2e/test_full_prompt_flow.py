import pytest
from llmops.app import App
from llmops.prompt_processing import process_prompt
from llmops.data_store import FeedbackStore

@pytest.fixture
def app():
    return App()

@pytest.fixture
def store():
    return FeedbackStore()

def test_full_prompt_flow(app, store):
    # Эмуляция полного сценария обработки запроса пользователя

    user_id = 42
    prompt = "Explain the principles of Tesla AI Genesis"
    
    # Шаг 1: Обработка промпта
    processed_prompt = process_prompt(prompt)
    assert processed_prompt is not None
    assert isinstance(processed_prompt, str)
    
    # Шаг 2: Отправка запроса в приложение
    response = app.handle_prompt(user_id, processed_prompt)
    assert response is not None
    assert "Tesla" in response  # Проверка, что ответ релевантен
    
    # Шаг 3: Сохранение обратной связи
    feedback = {
        "user_id": user_id,
        "prompt": prompt,
        "response": response,
        "rating": 5,
        "comment": "Очень полезный ответ"
    }
    save_result = store.save_feedback(feedback)
    assert save_result is True
    
    # Шаг 4: Проверка хранения обратной связи
    all_feedback = store.get_all_feedback()
    assert feedback in all_feedback
