import pytest
from fastapi.testclient import TestClient
from llmops.webapp import app
from llmops.data_store import FeedbackStore

client = TestClient(app)

def test_webapp_prompt_submission():
    # Проверка энд-ту-энд сценария отправки запроса через веб-приложение
    
    prompt_data = {
        "user_id": 101,
        "prompt": "What is Tesla AI Genesis?",
    }
    
    # Отправляем POST-запрос на эндпоинт подачи промпта
    response = client.post("/submit_prompt", json=prompt_data)
    
    assert response.status_code == 200
    json_resp = response.json()
    
    # Проверяем корректность ответа
    assert "response" in json_resp
    assert isinstance(json_resp["response"], str)
    assert len(json_resp["response"]) > 0
    
    # Проверяем, что ответ релевантен запросу
    assert "Tesla" in json_resp["response"]
    
    # Проверка сохранения обратной связи (если есть)
    store = FeedbackStore()
    feedbacks = store.get_all_feedback()
    # Ищем среди сохраненных обратных связей запрос пользователя
    found = any(fb["prompt"] == prompt_data["prompt"] for fb in feedbacks)
    assert found is True
