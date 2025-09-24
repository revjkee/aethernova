import pytest
from fastapi.testclient import TestClient
from llmops.webapp import app
from llmops.llm_model import LLMModel
from llmops.feedback import FeedbackProcessor

client = TestClient(app)

def test_feedback_loop_with_model():
    # Симуляция полного цикла: пользователь отправляет запрос, получает ответ,
    # отправляет фидбек, и система обновляет модель
    
    user_prompt = {"user_id": 202, "prompt": "Explain TeslaAI Genesis architecture."}
    
    # Отправляем запрос модели через API
    response = client.post("/submit_prompt", json=user_prompt)
    assert response.status_code == 200
    data = response.json()
    assert "response" in data
    initial_response = data["response"]
    assert isinstance(initial_response, str) and len(initial_response) > 0
    
    # Отправляем положительный фидбек по ответу
    feedback_payload = {
        "user_id": 202,
        "prompt": user_prompt["prompt"],
        "response": initial_response,
        "rating": 5,
        "comments": "Very clear explanation"
    }
    fb_response = client.post("/submit_feedback", json=feedback_payload)
    assert fb_response.status_code == 200
    fb_data = fb_response.json()
    assert fb_data.get("status") == "feedback received"
    
    # Проверяем, что фидбек обработан и учтен в системе
    processor = FeedbackProcessor()
    updated = processor.update_model_with_feedback(user_prompt["prompt"], feedback_payload)
    assert updated is True
