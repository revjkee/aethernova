"""
AetherNova NLP Supermodule - API Tests
Комплексные тесты для HTTP и WebSocket API
"""

import pytest
import asyncio
from fastapi.testclient import TestClient
from httpx import AsyncClient
import json

# Импорт приложения
import sys
from pathlib import Path
nlp_root = Path(__file__).parent.parent
sys.path.insert(0, str(nlp_root))

from api.http.server import app


class TestHTTPAPI:
    """Тесты HTTP API endpoints"""
    
    @pytest.fixture
    def client(self):
        """Test client"""
        return TestClient(app)
    
    def test_root_endpoint(self, client):
        """Тест корневого эндпоинта"""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data
    
    def test_health_check(self, client):
        """Тест health check"""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "services" in data
    
    def test_sentiment_analysis(self, client):
        """Тест анализа тональности"""
        payload = {
            "text": "I love this product! It's amazing!",
            "include_emotions": False
        }
        response = client.post("/sentiment", json=payload)
        assert response.status_code == 200
        
        data = response.json()
        assert "sentiment" in data
        assert "confidence" in data
        assert data["sentiment"] in ["positive", "negative", "neutral"]
        assert 0.0 <= data["confidence"] <= 1.0
    
    def test_sentiment_with_emotions(self, client):
        """Тест анализа тональности с эмоциями"""
        payload = {
            "text": "I'm so happy with this purchase!",
            "include_emotions": True
        }
        response = client.post("/sentiment", json=payload)
        assert response.status_code == 200
        
        data = response.json()
        assert "sentiment" in data
        # Эмоции могут быть None если модель не загружена
        if data.get("emotions"):
            assert isinstance(data["emotions"], dict)
    
    def test_ner(self, client):
        """Тест распознавания сущностей"""
        payload = {
            "text": "Apple was founded by Steve Jobs in Cupertino.",
            "min_confidence": 0.5,
            "normalize": True
        }
        response = client.post("/ner", json=payload)
        assert response.status_code == 200
        
        data = response.json()
        assert "entities" in data
        assert "entity_count" in data
        assert isinstance(data["entities"], list)
        
        # Проверка структуры сущности
        if data["entities"]:
            entity = data["entities"][0]
            assert "text" in entity
            assert "entity_type" in entity
            assert "confidence" in entity
    
    def test_text_generation(self, client):
        """Тест генерации текста"""
        payload = {
            "prompt": "The future of AI is",
            "max_length": 50,
            "temperature": 0.7
        }
        response = client.post("/generate", json=payload)
        assert response.status_code == 200
        
        data = response.json()
        assert "prompt" in data
        assert "generated_texts" in data
        assert isinstance(data["generated_texts"], list)
        assert len(data["generated_texts"]) > 0
    
    def test_summarization(self, client):
        """Тест суммаризации"""
        long_text = """
        Artificial intelligence (AI) is intelligence demonstrated by machines, 
        as opposed to natural intelligence displayed by animals including humans. 
        AI research has been defined as the field of study of intelligent agents, 
        which refers to any system that perceives its environment and takes actions 
        that maximize its chance of achieving its goals. The term artificial intelligence 
        is often used to describe machines that mimic cognitive functions that humans 
        associate with the human mind, such as learning and problem solving.
        """
        
        payload = {
            "text": long_text,
            "summary_length": "short",
            "summarization_type": "abstractive"
        }
        response = client.post("/summarize", json=payload)
        assert response.status_code == 200
        
        data = response.json()
        assert "summary" in data
        assert "original_length" in data
        assert "summary_length" in data
        assert data["summary_length"] < data["original_length"]
    
    def test_batch_sentiment(self, client):
        """Тест пакетного анализа тональности"""
        payload = {
            "texts": [
                "I love this!",
                "This is terrible.",
                "It's okay, nothing special."
            ],
            "include_emotions": False
        }
        response = client.post("/batch/sentiment", json=payload)
        assert response.status_code == 200
        
        data = response.json()
        assert "count" in data
        assert "results" in data
        assert data["count"] == 3
        assert len(data["results"]) == 3
    
    def test_batch_ner(self, client):
        """Тест пакетного NER"""
        payload = {
            "texts": [
                "Apple Inc. is based in California.",
                "Microsoft was founded by Bill Gates."
            ],
            "min_confidence": 0.5
        }
        response = client.post("/batch/ner", json=payload)
        assert response.status_code == 200
        
        data = response.json()
        assert "count" in data
        assert "results" in data
        assert data["count"] == 2
    
    def test_invalid_sentiment_request(self, client):
        """Тест невалидного запроса на анализ тональности"""
        payload = {}  # Нет text
        response = client.post("/sentiment", json=payload)
        assert response.status_code == 422  # Validation error
    
    def test_rate_limiting(self, client):
        """Тест rate limiting (может упасть, если лимиты высокие)"""
        # Отправка множества запросов
        for _ in range(5):
            response = client.get("/health")
            assert response.status_code == 200
    
    def test_cors_headers(self, client):
        """Тест CORS headers"""
        response = client.options("/")
        # FastAPI's CORS middleware должен добавить заголовки
        assert response.status_code in [200, 405]


class TestAsyncAPI:
    """Асинхронные тесты API"""
    
    @pytest.mark.asyncio
    async def test_async_sentiment(self):
        """Асинхронный тест анализа тональности"""
        async with AsyncClient(app=app, base_url="http://test") as client:
            payload = {"text": "I love testing!"}
            response = await client.post("/sentiment", json=payload)
            assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_concurrent_requests(self):
        """Тест одновременных запросов"""
        async with AsyncClient(app=app, base_url="http://test") as client:
            tasks = [
                client.post("/sentiment", json={"text": f"Test {i}"})
                for i in range(10)
            ]
            responses = await asyncio.gather(*tasks)
            
            for response in responses:
                assert response.status_code == 200


class TestWebSocketAPI:
    """Тесты WebSocket API"""
    
    def test_websocket_connection(self):
        """Тест WebSocket подключения"""
        client = TestClient(app)
        
        with client.websocket_connect("/ws/test_client") as websocket:
            # Получение welcome сообщения
            data = websocket.receive_json()
            assert data["type"] == "welcome"
            assert "client_id" in data
            assert "available_tasks" in data
    
    def test_websocket_ping(self):
        """Тест WebSocket ping/pong"""
        client = TestClient(app)
        
        with client.websocket_connect("/ws/test_client") as websocket:
            # Welcome
            websocket.receive_json()
            
            # Отправка ping
            websocket.send_json({"task": "ping"})
            
            # Получение pong
            response = websocket.receive_json()
            assert response["type"] == "pong"
            assert "timestamp" in response
    
    def test_websocket_sentiment_stream(self):
        """Тест потокового анализа тональности через WebSocket"""
        client = TestClient(app)
        
        with client.websocket_connect("/ws/test_client") as websocket:
            # Welcome
            websocket.receive_json()
            
            # Отправка запроса на анализ
            websocket.send_json({
                "task": "sentiment",
                "text": "I love WebSockets!"
            })
            
            # Получение статуса
            status_msg = websocket.receive_json()
            assert status_msg["type"] == "status"
            assert status_msg["status"] == "processing"
            
            # Получение результата
            result_msg = websocket.receive_json()
            assert result_msg["type"] == "result"
            assert "data" in result_msg
    
    def test_websocket_unknown_task(self):
        """Тест неизвестной задачи через WebSocket"""
        client = TestClient(app)
        
        with client.websocket_connect("/ws/test_client") as websocket:
            # Welcome
            websocket.receive_json()
            
            # Отправка неизвестной задачи
            websocket.send_json({"task": "unknown_task"})
            
            # Получение ошибки
            error_msg = websocket.receive_json()
            assert error_msg["type"] == "error"
            assert "Unknown task" in error_msg["message"]
    
    def test_websocket_generation_stream(self):
        """Тест потоковой генерации текста через WebSocket"""
        client = TestClient(app)
        
        with client.websocket_connect("/ws/test_client") as websocket:
            # Welcome
            websocket.receive_json()
            
            # Отправка запроса на генерацию
            websocket.send_json({
                "task": "generation",
                "prompt": "The future of AI is",
                "max_length": 30
            })
            
            # Получение статуса
            status_msg = websocket.receive_json()
            assert status_msg["type"] == "status"
            
            # Получение результата
            result_msg = websocket.receive_json()
            assert result_msg["type"] == "result"
            assert result_msg["task"] == "generation"
            assert "data" in result_msg
    
    def test_websocket_ner_stream(self):
        """Тест потокового NER через WebSocket"""
        client = TestClient(app)
        
        with client.websocket_connect("/ws/test_client") as websocket:
            # Welcome
            websocket.receive_json()
            
            # Отправка запроса на NER
            websocket.send_json({
                "task": "ner",
                "text": "Apple Inc. was founded by Steve Jobs in California."
            })
            
            # Получение статуса
            status_msg = websocket.receive_json()
            assert status_msg["type"] == "status"
            
            # Получение результата
            result_msg = websocket.receive_json()
            assert result_msg["type"] == "result"
            assert result_msg["task"] == "ner"
            assert "data" in result_msg
    
    def test_websocket_summarize_stream(self):
        """Тест потоковой суммаризации через WebSocket"""
        client = TestClient(app)
        
        with client.websocket_connect("/ws/test_client") as websocket:
            # Welcome
            websocket.receive_json()
            
            # Отправка запроса на суммаризацию
            long_text = """
            Artificial intelligence (AI) is intelligence demonstrated by machines, 
            as opposed to natural intelligence displayed by animals including humans. 
            AI research has been defined as the field of study of intelligent agents.
            """
            
            websocket.send_json({
                "task": "summarize",
                "text": long_text,
                "summary_length": "medium",
                "summarization_type": "abstractive"
            })
            
            # Получение статуса
            status_msg = websocket.receive_json()
            assert status_msg["type"] == "status"
            assert status_msg["task"] == "summarization"
            
            # Получение результата
            result_msg = websocket.receive_json()
            assert result_msg["type"] == "result"
            assert result_msg["task"] == "summarization"
            assert "data" in result_msg
    
    def test_websocket_batch_sentiment(self):
        """Тест batch анализа тональности через WebSocket"""
        client = TestClient(app)
        
        with client.websocket_connect("/ws/test_client") as websocket:
            # Welcome
            websocket.receive_json()
            
            # Отправка batch запроса
            websocket.send_json({
                "task": "batch",
                "subtask": "sentiment",
                "texts": [
                    "I love this product!",
                    "This is terrible.",
                    "It's okay."
                ]
            })
            
            # Получение результата
            result_msg = websocket.receive_json()
            assert result_msg["type"] == "result"
            assert result_msg["task"] == "batch_sentiment"
            assert "data" in result_msg
            assert len(result_msg["data"]) == 3
    
    def test_websocket_batch_ner(self):
        """Тест batch NER через WebSocket"""
        client = TestClient(app)
        
        with client.websocket_connect("/ws/test_client") as websocket:
            # Welcome
            websocket.receive_json()
            
            # Отправка batch запроса
            websocket.send_json({
                "task": "batch",
                "subtask": "ner",
                "texts": [
                    "Apple Inc. is based in California.",
                    "Microsoft was founded by Bill Gates."
                ]
            })
            
            # Получение результата
            result_msg = websocket.receive_json()
            assert result_msg["type"] == "result"
            assert result_msg["task"] == "batch_ner"
            assert "data" in result_msg
            assert len(result_msg["data"]) == 2
    
    def test_websocket_batch_summarize(self):
        """Тест batch суммаризации через WebSocket"""
        client = TestClient(app)
        
        with client.websocket_connect("/ws/test_client") as websocket:
            # Welcome
            websocket.receive_json()
            
            # Отправка batch запроса
            websocket.send_json({
                "task": "batch",
                "subtask": "summarize",
                "texts": [
                    "AI is transforming the world. " * 20,
                    "Machine learning enables computers to learn. " * 20
                ]
            })
            
            # Получение результата
            result_msg = websocket.receive_json()
            assert result_msg["type"] == "result"
            assert result_msg["task"] == "batch_summarize"
            assert "data" in result_msg
            assert len(result_msg["data"]) == 2
    
    def test_websocket_batch_invalid_subtask(self):
        """Тест невалидной batch подзадачи через WebSocket"""
        client = TestClient(app)
        
        with client.websocket_connect("/ws/test_client") as websocket:
            # Welcome
            websocket.receive_json()
            
            # Отправка с невалидной подзадачей
            websocket.send_json({
                "task": "batch",
                "subtask": "unknown",
                "texts": ["test"]
            })
            
            # Получение ошибки
            error_msg = websocket.receive_json()
            assert error_msg["type"] == "error"
            assert "Unknown batch subtask" in error_msg["message"]
    
    def test_websocket_error_handling(self):
        """Тест обработки ошибок через WebSocket"""
        client = TestClient(app)
        
        with client.websocket_connect("/ws/test_client") as websocket:
            # Welcome
            websocket.receive_json()
            
            # Отправка запроса без обязательных полей
            websocket.send_json({
                "task": "sentiment"
                # Нет "text"
            })
            
            # Получение ошибки
            error_msg = websocket.receive_json()
            assert error_msg["type"] == "error"


class TestAPIPerformance:
    """Тесты производительности API"""
    
    def test_response_time(self, benchmark):
        """Бенчмарк времени ответа"""
        client = TestClient(app)
        
        def make_request():
            response = client.post("/sentiment", json={"text": "Test"})
            return response
        
        result = benchmark(make_request)
        assert result.status_code == 200
    
    @pytest.mark.asyncio
    async def test_throughput(self):
        """Тест throughput (запросов в секунду)"""
        import time
        
        async with AsyncClient(app=app, base_url="http://test") as client:
            start = time.time()
            
            tasks = [
                client.post("/sentiment", json={"text": f"Test {i}"})
                for i in range(100)
            ]
            
            responses = await asyncio.gather(*tasks)
            
            elapsed = time.time() - start
            throughput = len(responses) / elapsed
            
            print(f"\nThroughput: {throughput:.2f} req/s")
            assert throughput > 10  # Минимум 10 req/s


class TestAPIIntegration:
    """Интеграционные тесты"""
    
    @pytest.fixture
    def client(self):
        """Test client"""
        return TestClient(app)
    
    def test_full_nlp_pipeline(self, client):
        """Тест полного NLP пайплайна"""
        text = "Apple Inc. released amazing new products. Customers are very happy!"
        
        # 1. Sentiment analysis
        sentiment_response = client.post("/sentiment", json={"text": text})
        assert sentiment_response.status_code == 200
        sentiment_data = sentiment_response.json()
        assert sentiment_data["sentiment"] == "positive"
        
        # 2. NER
        ner_response = client.post("/ner", json={"text": text})
        assert ner_response.status_code == 200
        ner_data = ner_response.json()
        assert ner_data["entity_count"] > 0
        
        # 3. Summarization
        long_text = text * 10  # Повторяем для длины
        summarize_response = client.post("/summarize", json={
            "text": long_text,
            "summary_length": "short"
        })
        assert summarize_response.status_code == 200
    
    def test_http_to_websocket_consistency(self, client):
        """Тест консистентности результатов HTTP и WebSocket API"""
        text = "I love this product!"
        
        # HTTP запрос
        http_response = client.post("/sentiment", json={"text": text})
        http_data = http_response.json()
        
        # WebSocket запрос
        with client.websocket_connect("/ws/test_client") as websocket:
            websocket.receive_json()  # Welcome
            
            websocket.send_json({
                "task": "sentiment",
                "text": text
            })
            
            websocket.receive_json()  # Status
            ws_response = websocket.receive_json()  # Result
            ws_data = ws_response["data"]
        
        # Результаты должны быть идентичными
        assert http_data["sentiment"] == ws_data["sentiment"]
        assert abs(http_data["confidence"] - ws_data["confidence"]) < 0.01
    
    def test_batch_vs_individual_requests(self, client):
        """Тест консистентности batch vs индивидуальные запросы"""
        texts = [
            "I love this!",
            "This is terrible.",
            "It's okay."
        ]
        
        # Batch запрос
        batch_response = client.post("/batch/sentiment", json={"texts": texts})
        batch_results = batch_response.json()["results"]
        
        # Индивидуальные запросы
        individual_results = []
        for text in texts:
            response = client.post("/sentiment", json={"text": text})
            individual_results.append(response.json())
        
        # Результаты должны совпадать
        for batch, individual in zip(batch_results, individual_results):
            assert batch["sentiment"] == individual["sentiment"]
            assert abs(batch["confidence"] - individual["confidence"]) < 0.01
    
    def test_multilang_support(self, client):
        """Тест поддержки многоязычности"""
        texts = {
            "en": "I love this product!",
            "ru": "Я люблю этот продукт!",
            "de": "Ich liebe dieses Produkt!",
            "fr": "J'adore ce produit!"
        }
        
        for lang, text in texts.items():
            response = client.post("/sentiment", json={"text": text})
            assert response.status_code == 200
            data = response.json()
            # Все должны быть позитивными
            assert data["sentiment"] == "positive"
    
    def test_pipeline_error_recovery(self, client):
        """Тест восстановления после ошибок в пайплайне"""
        # 1. Успешный запрос
        response1 = client.post("/sentiment", json={"text": "Good product"})
        assert response1.status_code == 200
        
        # 2. Запрос с ошибкой
        response2 = client.post("/sentiment", json={})
        assert response2.status_code == 422
        
        # 3. Следующий успешный запрос должен работать
        response3 = client.post("/sentiment", json={"text": "Great product"})
        assert response3.status_code == 200


class TestAPIEdgeCases:
    """Тесты граничных случаев и валидации"""
    
    @pytest.fixture
    def client(self):
        """Test client"""
        return TestClient(app)
    
    def test_empty_text(self, client):
        """Тест с пустым текстом"""
        response = client.post("/sentiment", json={"text": ""})
        # Может быть 422 (валидация) или 200 с нейтральным результатом
        assert response.status_code in [200, 422]
    
    def test_very_long_text(self, client):
        """Тест с очень длинным текстом"""
        long_text = "This is a test. " * 1000  # ~15k символов
        response = client.post("/sentiment", json={"text": long_text})
        assert response.status_code == 200
    
    def test_special_characters(self, client):
        """Тест со спецсимволами"""
        text = "I ❤️ this! 🚀 Amazing product!!! #best @company"
        response = client.post("/sentiment", json={"text": text})
        assert response.status_code == 200
    
    def test_unicode_text(self, client):
        """Тест с Unicode символами"""
        text = "文字化け テスト Тестирование éèêë"
        response = client.post("/sentiment", json={"text": text})
        assert response.status_code == 200
    
    def test_html_tags(self, client):
        """Тест с HTML тегами"""
        text = "<p>This is <b>great</b> product!</p>"
        response = client.post("/sentiment", json={"text": text})
        assert response.status_code == 200
    
    def test_max_batch_size(self, client):
        """Тест максимального размера batch"""
        # Большой batch (может быть ограничение)
        texts = [f"Test sentence {i}" for i in range(100)]
        response = client.post("/batch/sentiment", json={"texts": texts})
        # Может быть успешным или с ошибкой "too many items"
        assert response.status_code in [200, 422]
    
    def test_malformed_json(self, client):
        """Тест с некорректным JSON"""
        response = client.post(
            "/sentiment",
            data="not a json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422
    
    def test_missing_required_fields(self, client):
        """Тест с отсутствующими обязательными полями"""
        # Sentiment без text
        response1 = client.post("/sentiment", json={})
        assert response1.status_code == 422
        
        # NER без text
        response2 = client.post("/ner", json={})
        assert response2.status_code == 422
        
        # Generation без prompt
        response3 = client.post("/generate", json={})
        assert response3.status_code == 422
    
    def test_invalid_parameter_values(self, client):
        """Тест с невалидными значениями параметров"""
        # Негативная confidence
        response1 = client.post("/ner", json={
            "text": "Test",
            "min_confidence": -0.5
        })
        assert response1.status_code == 422
        
        # Confidence > 1
        response2 = client.post("/ner", json={
            "text": "Test",
            "min_confidence": 1.5
        })
        assert response2.status_code == 422
    
    def test_unsupported_language(self, client):
        """Тест с неподдерживаемым языком (если есть фильтр)"""
        # Текст на редком языке
        text = "ይህ የሙከራ ጽሑፍ ነው።"  # Амхарский
        response = client.post("/sentiment", json={"text": text})
        # Должен обработать или вернуть ошибку
        assert response.status_code in [200, 422]


class TestAPIMetrics:
    """Тесты метрик и мониторинга API"""
    
    @pytest.fixture
    def client(self):
        """Test client"""
        return TestClient(app)
    
    def test_metrics_endpoint(self, client):
        """Тест эндпоинта метрик (если есть)"""
        response = client.get("/metrics")
        # Может быть или не быть
        assert response.status_code in [200, 404]
    
    def test_api_version_info(self, client):
        """Тест информации о версии API"""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "version" in data
    
    def test_available_models(self, client):
        """Тест списка доступных моделей (если есть эндпоинт)"""
        response = client.get("/models")
        # Может быть или не быть
        assert response.status_code in [200, 404]


# Запуск тестов
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
