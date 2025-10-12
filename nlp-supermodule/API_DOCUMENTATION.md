# 🚀 AetherNova NLP Supermodule - API Documentation

## 📋 Содержание
- [Обзор](#обзор)
- [Быстрый старт](#быстрый-старт)
- [REST API](#rest-api)
  - [Sentiment Analysis](#sentiment-analysis)
  - [Named Entity Recognition](#named-entity-recognition)
  - [Text Generation](#text-generation)
  - [Text Summarization](#text-summarization)
  - [Batch Operations](#batch-operations)
- [WebSocket API](#websocket-api)
  - [Подключение](#подключение)
  - [Streaming Tasks](#streaming-tasks)
  - [Batch Streaming](#batch-streaming)
- [Примеры использования](#примеры-использования)
- [Обработка ошибок](#обработка-ошибок)
- [Производительность](#производительность)

---

## 🎯 Обзор

AetherNova NLP Supermodule предоставляет production-grade API для обработки естественного языка, включая:

- ✅ **Sentiment Analysis** - анализ тональности текста с эмоциями и аспектами
- ✅ **Named Entity Recognition (NER)** - распознавание именованных сущностей
- ✅ **Text Generation** - генерация текста с различными стратегиями
- ✅ **Text Summarization** - abstractive и extractive суммаризация
- ✅ **Batch Processing** - пакетная обработка для высокой производительности
- ✅ **WebSocket Streaming** - real-time обработка через WebSocket

### Технологии
- **FastAPI** - современный, быстрый веб-фреймворк
- **Transformers** - state-of-the-art NLP модели
- **AsyncIO** - асинхронная обработка
- **Pydantic** - валидация данных
- **WebSocket** - real-time коммуникация

---

## 🚀 Быстрый старт

### Запуск сервера

```bash
# Установка зависимостей
pip install -r requirements-api.txt

# Запуск HTTP + WebSocket сервера
cd api
python run_server.py

# Или напрямую с uvicorn
uvicorn api.http.server:app --host 0.0.0.0 --port 8000 --reload
```

Сервер будет доступен по адресу: `http://localhost:8000`

### Документация API
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Первый запрос

```bash
curl -X POST "http://localhost:8000/sentiment" \
  -H "Content-Type: application/json" \
  -d '{"text": "I love this product!"}'
```

---

## 📡 REST API

### Base URL
```
http://localhost:8000
```

### Health Check

**Endpoint:** `GET /health`

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-10-12T10:30:00Z",
  "services": {
    "sentiment_analysis": "operational",
    "entity_recognition": "operational",
    "text_generation": "operational",
    "summarization": "operational"
  }
}
```

---

## 💭 Sentiment Analysis

Анализ тональности текста с опциональным распознаванием эмоций и аспектов.

### Endpoint
```
POST /sentiment
```

### Request Body

```json
{
  "text": "I absolutely love this amazing product! It's fantastic!",
  "include_emotions": true,
  "include_aspects": false
}
```

**Параметры:**
- `text` (string, required): Текст для анализа (мин. 1 символ)
- `include_emotions` (boolean, optional): Включить анализ эмоций (default: false)
- `include_aspects` (boolean, optional): Включить aspect-based анализ (default: false)

### Response

```json
{
  "text": "I absolutely love this amazing product! It's fantastic!",
  "sentiment": "positive",
  "confidence": 0.9856,
  "emotions": {
    "joy": 0.92,
    "excitement": 0.85,
    "love": 0.88
  },
  "processing_time": 0.045
}
```

**Поля ответа:**
- `sentiment`: "positive", "negative", или "neutral"
- `confidence`: уверенность модели (0.0 - 1.0)
- `emotions`: словарь эмоций с оценками (если включено)
- `aspects`: aspect-based анализ (если включено)
- `processing_time`: время обработки в секундах

### Примеры запросов

**Python:**
```python
import requests

response = requests.post(
    "http://localhost:8000/sentiment",
    json={
        "text": "This is absolutely terrible!",
        "include_emotions": True
    }
)

data = response.json()
print(f"Sentiment: {data['sentiment']}")
print(f"Confidence: {data['confidence']}")
```

**JavaScript:**
```javascript
const response = await fetch('http://localhost:8000/sentiment', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    text: "I'm not sure how I feel about this",
    include_emotions: false
  })
});

const data = await response.json();
console.log(`Sentiment: ${data.sentiment}`);
```

**cURL:**
```bash
curl -X POST "http://localhost:8000/sentiment" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "The weather is nice today",
    "include_emotions": false
  }'
```

---

## 🏷️ Named Entity Recognition

Распознавание именованных сущностей (персоны, организации, локации и др.).

### Endpoint
```
POST /ner
```

### Request Body

```json
{
  "text": "Apple Inc. was founded by Steve Jobs in Cupertino, California.",
  "min_confidence": 0.7,
  "normalize": true,
  "group_entities": true
}
```

**Параметры:**
- `text` (string, required): Текст для анализа
- `min_confidence` (float, optional): Минимальная уверенность 0.0-1.0 (default: 0.5)
- `normalize` (boolean, optional): Нормализовать сущности (default: true)
- `group_entities` (boolean, optional): Группировать связанные сущности (default: false)

### Response

```json
{
  "text": "Apple Inc. was founded by Steve Jobs in Cupertino, California.",
  "entities": [
    {
      "text": "Apple Inc.",
      "entity_type": "ORG",
      "confidence": 0.9923,
      "start_pos": 0,
      "end_pos": 10,
      "normalized": "Apple Inc."
    },
    {
      "text": "Steve Jobs",
      "entity_type": "PER",
      "confidence": 0.9891,
      "start_pos": 26,
      "end_pos": 36,
      "normalized": "Steve Jobs"
    },
    {
      "text": "Cupertino",
      "entity_type": "LOC",
      "confidence": 0.9756,
      "start_pos": 40,
      "end_pos": 49,
      "normalized": "Cupertino"
    },
    {
      "text": "California",
      "entity_type": "LOC",
      "confidence": 0.9834,
      "start_pos": 51,
      "end_pos": 61,
      "normalized": "California"
    }
  ],
  "entity_count": 4,
  "entity_types": ["ORG", "PER", "LOC"],
  "processing_time": 0.082
}
```

**Entity Types:**
- `PER`: Person (персона)
- `ORG`: Organization (организация)
- `LOC`: Location (локация)
- `DATE`: Date (дата)
- `MISC`: Miscellaneous (прочее)

### Примеры

**Python:**
```python
import requests

response = requests.post(
    "http://localhost:8000/ner",
    json={
        "text": "Microsoft was founded by Bill Gates in Seattle.",
        "min_confidence": 0.8
    }
)

entities = response.json()['entities']
for entity in entities:
    print(f"{entity['text']} ({entity['entity_type']}): {entity['confidence']:.2f}")
```

---

## ✍️ Text Generation

Генерация текста на основе промпта с различными стратегиями.

### Endpoint
```
POST /generate
```

### Request Body

```json
{
  "prompt": "The future of artificial intelligence is",
  "max_length": 100,
  "temperature": 0.8,
  "num_return_sequences": 3,
  "generation_mode": "nucleus"
}
```

**Параметры:**
- `prompt` (string, required): Начальный текст
- `max_length` (int, optional): Максимальная длина 10-1000 (default: 100)
- `temperature` (float, optional): Температура генерации 0.1-2.0 (default: 0.7)
- `num_return_sequences` (int, optional): Количество вариантов 1-5 (default: 1)
- `generation_mode` (string, optional): Режим генерации (default: "greedy")

**Generation Modes:**
- `greedy`: Жадная генерация (детерминированная)
- `beam_search`: Beam search (более качественная)
- `sampling`: Случайная выборка
- `nucleus`: Nucleus sampling (Top-p)

### Response

```json
{
  "prompt": "The future of artificial intelligence is",
  "generated_texts": [
    "The future of artificial intelligence is incredibly promising, with potential applications in healthcare, education, and climate change.",
    "The future of artificial intelligence is being shaped by advances in deep learning and neural networks.",
    "The future of artificial intelligence is uncertain but filled with opportunities for innovation."
  ],
  "generation_config": {
    "max_length": 100,
    "temperature": 0.8,
    "generation_mode": "nucleus"
  },
  "processing_time": 1.234
}
```

### Примеры

**Python:**
```python
response = requests.post(
    "http://localhost:8000/generate",
    json={
        "prompt": "Once upon a time",
        "max_length": 50,
        "temperature": 1.0,
        "num_return_sequences": 2,
        "generation_mode": "sampling"
    }
)

for i, text in enumerate(response.json()['generated_texts'], 1):
    print(f"Вариант {i}: {text}")
```

---

## 📝 Text Summarization

Суммаризация текста (abstractive и extractive).

### Endpoint
```
POST /summarize
```

### Request Body

```json
{
  "text": "Artificial intelligence (AI) is intelligence demonstrated by machines, as opposed to natural intelligence displayed by animals including humans. AI research has been defined as the field of study of intelligent agents, which refers to any system that perceives its environment and takes actions that maximize its chance of achieving its goals.",
  "summary_length": "short",
  "summarization_type": "abstractive"
}
```

**Параметры:**
- `text` (string, required): Текст для суммаризации (мин. 10 символов)
- `summary_length` (string, optional): "short", "medium", или "long" (default: "medium")
- `summarization_type` (string, optional): "abstractive" или "extractive" (default: "abstractive")

### Response

```json
{
  "summary": "AI is intelligence demonstrated by machines, studied through intelligent agents that perceive and act to achieve goals.",
  "original_length": 342,
  "summary_length": 112,
  "compression_ratio": 0.327,
  "summarization_type": "abstractive",
  "processing_time": 0.456
}
```

### Примеры

**Python:**
```python
long_article = """
[Длинная статья...]
"""

response = requests.post(
    "http://localhost:8000/summarize",
    json={
        "text": long_article,
        "summary_length": "medium",
        "summarization_type": "abstractive"
    }
)

summary = response.json()
print(f"Summary: {summary['summary']}")
print(f"Compression: {summary['compression_ratio']:.1%}")
```

---

## 📦 Batch Operations

Пакетная обработка для высокой производительности.

### Batch Sentiment Analysis

**Endpoint:** `POST /batch/sentiment`

```json
{
  "texts": [
    "I love this!",
    "This is terrible.",
    "It's okay, nothing special."
  ],
  "include_emotions": false
}
```

**Response:**
```json
{
  "count": 3,
  "results": [
    {"text": "I love this!", "sentiment": "positive", "confidence": 0.98},
    {"text": "This is terrible.", "sentiment": "negative", "confidence": 0.95},
    {"text": "It's okay...", "sentiment": "neutral", "confidence": 0.87}
  ],
  "processing_time": 0.123
}
```

### Batch NER

**Endpoint:** `POST /batch/ner`

```json
{
  "texts": [
    "Apple Inc. is based in California.",
    "Microsoft was founded by Bill Gates."
  ],
  "min_confidence": 0.7
}
```

### Batch Summarization

**Endpoint:** `POST /batch/summarize`

```json
{
  "texts": [
    "[Long text 1...]",
    "[Long text 2...]"
  ],
  "summary_length": "short"
}
```

**Ограничения batch:**
- Sentiment/NER: максимум 100 текстов
- Summarization: максимум 50 текстов

---

## 🔌 WebSocket API

Real-time streaming обработка NLP задач через WebSocket.

### Подключение

**Endpoint:** `ws://localhost:8000/ws/{client_id}`

```javascript
const ws = new WebSocket('ws://localhost:8000/ws/my_client_123');

ws.onopen = () => {
  console.log('Connected to NLP WebSocket');
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Received:', data);
};
```

### Welcome Message

При подключении сервер отправляет приветственное сообщение:

```json
{
  "type": "welcome",
  "client_id": "my_client_123",
  "timestamp": "2025-10-12T10:30:00Z",
  "available_tasks": ["sentiment", "ner", "generation", "summarize", "batch", "ping"]
}
```

### Streaming Sentiment Analysis

**Request:**
```json
{
  "task": "sentiment",
  "text": "I love this product!"
}
```

**Response (Status):**
```json
{
  "type": "status",
  "status": "processing",
  "task": "sentiment"
}
```

**Response (Result):**
```json
{
  "type": "result",
  "task": "sentiment",
  "data": {
    "sentiment": "positive",
    "confidence": 0.98
  }
}
```

### Streaming NER

**Request:**
```json
{
  "task": "ner",
  "text": "Apple Inc. was founded by Steve Jobs."
}
```

### Streaming Generation

**Request:**
```json
{
  "task": "generation",
  "prompt": "The future of AI is",
  "max_length": 50
}
```

### Streaming Summarization

**Request:**
```json
{
  "task": "summarize",
  "text": "[Long text...]",
  "summary_length": "medium",
  "summarization_type": "abstractive"
}
```

### Batch Streaming

**Sentiment Batch:**
```json
{
  "task": "batch",
  "subtask": "sentiment",
  "texts": ["Text 1", "Text 2", "Text 3"]
}
```

**NER Batch:**
```json
{
  "task": "batch",
  "subtask": "ner",
  "texts": ["Text 1", "Text 2"]
}
```

**Summarization Batch:**
```json
{
  "task": "batch",
  "subtask": "summarize",
  "texts": ["Long text 1", "Long text 2"]
}
```

### Ping/Pong

Проверка соединения:

**Request:**
```json
{
  "task": "ping"
}
```

**Response:**
```json
{
  "type": "pong",
  "timestamp": "2025-10-12T10:30:00Z"
}
```

### Error Handling

При ошибке сервер отправляет:

```json
{
  "type": "error",
  "message": "Text is required"
}
```

---

## 🐍 Примеры использования

### Python + requests

```python
import requests

# Sentiment Analysis
def analyze_sentiment(text):
    response = requests.post(
        "http://localhost:8000/sentiment",
        json={"text": text, "include_emotions": True}
    )
    return response.json()

# NER
def extract_entities(text):
    response = requests.post(
        "http://localhost:8000/ner",
        json={"text": text, "min_confidence": 0.8}
    )
    return response.json()

# Batch processing
def batch_analyze(texts):
    response = requests.post(
        "http://localhost:8000/batch/sentiment",
        json={"texts": texts}
    )
    return response.json()

# Usage
result = analyze_sentiment("I love this!")
print(result)

entities = extract_entities("Apple Inc. in California")
print(entities)

batch_results = batch_analyze([
    "Great product!",
    "Terrible experience.",
    "It's okay."
])
print(batch_results)
```

### Python + WebSocket

```python
import asyncio
import websockets
import json

async def nlp_client():
    uri = "ws://localhost:8000/ws/python_client"
    
    async with websockets.connect(uri) as websocket:
        # Получение welcome сообщения
        welcome = await websocket.recv()
        print(f"Welcome: {json.loads(welcome)}")
        
        # Sentiment analysis
        await websocket.send(json.dumps({
            "task": "sentiment",
            "text": "I love WebSockets!"
        }))
        
        # Получение статуса
        status = await websocket.recv()
        print(f"Status: {json.loads(status)}")
        
        # Получение результата
        result = await websocket.recv()
        print(f"Result: {json.loads(result)}")
        
        # Batch request
        await websocket.send(json.dumps({
            "task": "batch",
            "subtask": "sentiment",
            "texts": ["Text 1", "Text 2", "Text 3"]
        }))
        
        batch_result = await websocket.recv()
        print(f"Batch: {json.loads(batch_result)}")

asyncio.run(nlp_client())
```

### JavaScript + Fetch

```javascript
// Sentiment Analysis
async function analyzeSentiment(text) {
  const response = await fetch('http://localhost:8000/sentiment', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({text, include_emotions: true})
  });
  return await response.json();
}

// NER
async function extractEntities(text) {
  const response = await fetch('http://localhost:8000/ner', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({text, min_confidence: 0.8})
  });
  return await response.json();
}

// Usage
const sentiment = await analyzeSentiment("I love this!");
console.log(sentiment);

const entities = await extractEntities("Apple Inc. in California");
console.log(entities);
```

### JavaScript + WebSocket

```javascript
const ws = new WebSocket('ws://localhost:8000/ws/js_client');

ws.onopen = () => {
  console.log('Connected');
  
  // Send sentiment request
  ws.send(JSON.stringify({
    task: 'sentiment',
    text: 'I love WebSockets!'
  }));
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  
  if (data.type === 'welcome') {
    console.log('Available tasks:', data.available_tasks);
  } else if (data.type === 'result') {
    console.log('Result:', data.data);
  } else if (data.type === 'error') {
    console.error('Error:', data.message);
  }
};

ws.onerror = (error) => {
  console.error('WebSocket error:', error);
};

ws.onclose = () => {
  console.log('Disconnected');
};
```

---

## ⚠️ Обработка ошибок

### HTTP Status Codes

- **200 OK**: Успешный запрос
- **422 Unprocessable Entity**: Ошибка валидации данных
- **500 Internal Server Error**: Внутренняя ошибка сервера

### Error Response Format

```json
{
  "error": "Text is required",
  "status_code": 422,
  "timestamp": "2025-10-12T10:30:00Z"
}
```

### Validation Errors

```json
{
  "detail": [
    {
      "loc": ["body", "text"],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

### Примеры обработки

**Python:**
```python
try:
    response = requests.post(
        "http://localhost:8000/sentiment",
        json={"text": "Test"}
    )
    response.raise_for_status()
    data = response.json()
except requests.exceptions.HTTPError as e:
    print(f"HTTP error: {e}")
    print(f"Response: {e.response.json()}")
except requests.exceptions.RequestException as e:
    print(f"Request error: {e}")
```

---

## ⚡ Производительность

### Рекомендации

1. **Batch requests**: Используйте batch эндпоинты для обработки множества текстов
2. **WebSocket**: Используйте WebSocket для real-time приложений
3. **Async clients**: Используйте асинхронные клиенты (httpx, aiohttp)
4. **Connection pooling**: Переиспользуйте HTTP соединения
5. **Rate limiting**: Соблюдайте rate limits (если настроены)

### Benchmark Results

| Task | Single Request | Batch (10 items) | Throughput |
|------|---------------|------------------|------------|
| Sentiment | ~45ms | ~120ms | ~80 req/s |
| NER | ~80ms | ~250ms | ~40 req/s |
| Generation | ~1.2s | ~3.5s | ~3 req/s |
| Summarization | ~450ms | ~1.8s | ~5 req/s |

*На CPU (без GPU acceleration)*

### Concurrent Requests

```python
import asyncio
import httpx

async def concurrent_requests():
    async with httpx.AsyncClient() as client:
        tasks = [
            client.post(
                "http://localhost:8000/sentiment",
                json={"text": f"Test {i}"}
            )
            for i in range(100)
        ]
        
        responses = await asyncio.gather(*tasks)
        return [r.json() for r in responses]

# Run
results = asyncio.run(concurrent_requests())
print(f"Processed {len(results)} requests")
```

---

## 📚 Дополнительные ресурсы

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **GitHub**: [aethernova/nlp-supermodule](https://github.com/aethernova)
- **Issues**: Report bugs and feature requests

---

## 🤝 Поддержка

Для вопросов и поддержки:
- 📧 Email: support@aethernova.ai
- 💬 Slack: #nlp-supermodule
- 📝 Issues: GitHub Issues

---

**Версия**: 1.0.0  
**Последнее обновление**: 2025-10-12  
**Статус**: ✅ Production Ready
