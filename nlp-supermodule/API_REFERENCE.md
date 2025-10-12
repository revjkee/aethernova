# NLP Supermodule API Reference

## Table of Contents
- [Authentication](#authentication)
- [Rate Limiting](#rate-limiting)
- [Error Handling](#error-handling)
- [HTTP Endpoints](#http-endpoints)
- [WebSocket Protocol](#websocket-protocol)
- [Request/Response Examples](#requestresponse-examples)
- [Client Libraries](#client-libraries)

---

## Authentication

**Current Status**: No authentication required (development mode)

**Future**: JWT-based authentication will be required for production deployments.

```bash
# Future authentication header
Authorization: Bearer <jwt_token>
```

---

## Rate Limiting

### Limits by Endpoint

| Endpoint | Rate Limit | Window |
|----------|------------|--------|
| `/sentiment` | 100 requests | per minute |
| `/ner` | 100 requests | per minute |
| `/generate` | 50 requests | per minute |
| `/summarize` | 50 requests | per minute |
| `/batch/sentiment` | 20 requests | per minute |
| `/batch/ner` | 20 requests | per minute |
| `/batch/summarize` | 10 requests | per minute |
| WebSocket `/ws/{client_id}` | 200 messages | per minute |

### Rate Limit Response

When rate limit is exceeded:
```json
{
  "error": "Rate limit exceeded: 100 per 1 minute",
  "status": 429,
  "retry_after": 45
}
```

Headers:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1697123456
```

---

## Error Handling

### HTTP Status Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 200 | OK | Request successful |
| 400 | Bad Request | Invalid input parameters |
| 422 | Unprocessable Entity | Validation error |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error |

### Error Response Format

```json
{
  "detail": "Error message",
  "timestamp": "2025-10-12T14:30:00Z",
  "path": "/sentiment",
  "error_type": "ValidationError"
}
```

---

## HTTP Endpoints

### 1. Sentiment Analysis

**Endpoint**: `POST /sentiment`  
**Rate Limit**: 100/min

#### Request Body
```json
{
  "text": "string (required, max 5000 chars)",
  "include_emotions": "boolean (optional, default: false)",
  "include_aspects": "boolean (optional, default: false)",
  "language": "string (optional, default: 'en')"
}
```

#### Response
```json
{
  "text": "I love this product!",
  "sentiment": "positive",
  "confidence": 0.9876,
  "scores": {
    "positive": 0.9876,
    "negative": 0.0089,
    "neutral": 0.0035
  },
  "emotions": {
    "joy": 0.8234,
    "surprise": 0.1234,
    "anger": 0.0123,
    "sadness": 0.0089,
    "fear": 0.0123,
    "disgust": 0.0097
  },
  "aspects": [
    {
      "aspect": "product",
      "sentiment": "positive",
      "confidence": 0.95
    }
  ]
}
```

#### Example
```bash
curl -X POST "http://localhost:8000/sentiment" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "I love this product but hate the price.",
    "include_emotions": true,
    "include_aspects": true
  }'
```

---

### 2. Named Entity Recognition

**Endpoint**: `POST /ner`  
**Rate Limit**: 100/min

#### Request Body
```json
{
  "text": "string (required, max 10000 chars)",
  "min_confidence": "float (optional, default: 0.5)",
  "entity_types": "array[string] (optional, default: all)",
  "language": "string (optional, default: 'en')"
}
```

#### Response
```json
{
  "text": "Apple was founded by Steve Jobs in Cupertino in 1976.",
  "entities": [
    {
      "text": "Apple",
      "entity_type": "ORGANIZATION",
      "start": 0,
      "end": 5,
      "confidence": 0.9823,
      "context": "Apple was founded by..."
    },
    {
      "text": "Steve Jobs",
      "entity_type": "PERSON",
      "start": 21,
      "end": 31,
      "confidence": 0.9956,
      "context": "...founded by Steve Jobs in..."
    },
    {
      "text": "Cupertino",
      "entity_type": "LOCATION",
      "start": 35,
      "end": 44,
      "confidence": 0.9712,
      "context": "...Jobs in Cupertino in 1976."
    },
    {
      "text": "1976",
      "entity_type": "DATE",
      "start": 48,
      "end": 52,
      "confidence": 0.9889,
      "context": "...Cupertino in 1976."
    }
  ],
  "entities_by_type": {
    "ORGANIZATION": ["Apple"],
    "PERSON": ["Steve Jobs"],
    "LOCATION": ["Cupertino"],
    "DATE": ["1976"]
  }
}
```

#### Supported Entity Types
- `PERSON` - People, including fictional
- `ORGANIZATION` - Companies, agencies, institutions
- `LOCATION` - Countries, cities, states
- `DATE` - Absolute or relative dates or periods
- `TIME` - Times smaller than a day
- `MONEY` - Monetary values, including unit
- `PERCENT` - Percentage values
- `PRODUCT` - Objects, vehicles, foods, etc.
- `EVENT` - Named hurricanes, battles, wars, sports events, etc.
- `LANGUAGE` - Any named language
- `MISCELLANEOUS` - Other entities

#### Example
```bash
curl -X POST "http://localhost:8000/ner" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Microsoft was founded by Bill Gates in Seattle.",
    "min_confidence": 0.7,
    "entity_types": ["PERSON", "ORGANIZATION", "LOCATION"]
  }'
```

---

### 3. Text Generation

**Endpoint**: `POST /generate`  
**Rate Limit**: 50/min

#### Request Body
```json
{
  "prompt": "string (required, max 2000 chars)",
  "max_length": "integer (optional, default: 100, max: 500)",
  "temperature": "float (optional, default: 0.7, range: 0.0-2.0)",
  "top_k": "integer (optional, default: 50)",
  "top_p": "float (optional, default: 0.9)",
  "num_return_sequences": "integer (optional, default: 1, max: 5)",
  "mode": "string (optional, default: 'sampling')"
}
```

#### Generation Modes
- `greedy` - Always pick the most likely next token
- `beam` - Beam search with multiple hypotheses
- `sampling` - Random sampling with temperature
- `top_k` - Sample from top K most likely tokens
- `top_p` - Nucleus sampling (cumulative probability)

#### Response
```json
{
  "prompt": "The future of AI is",
  "generated_texts": [
    "The future of AI is bright and full of possibilities. Machine learning models are becoming more sophisticated, enabling breakthroughs in healthcare, education, and scientific research."
  ],
  "generation_config": {
    "max_length": 100,
    "temperature": 0.7,
    "mode": "sampling"
  },
  "perplexity": 12.34
}
```

#### Example
```bash
curl -X POST "http://localhost:8000/generate" \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Once upon a time",
    "max_length": 150,
    "temperature": 0.8,
    "num_return_sequences": 3,
    "mode": "top_p"
  }'
```

---

### 4. Text Summarization

**Endpoint**: `POST /summarize`  
**Rate Limit**: 50/min

#### Request Body
```json
{
  "text": "string (required, max 50000 chars)",
  "summary_type": "string (optional, default: 'abstractive')",
  "summary_length": "string (optional, default: 'MEDIUM')",
  "max_length": "integer (optional)",
  "min_length": "integer (optional)",
  "num_sentences": "integer (optional, for extractive)"
}
```

#### Summary Types
- `abstractive` - Generate new text (like a human would)
- `extractive` - Extract key sentences from original

#### Summary Lengths
- `SHORT` - 10-50 words
- `MEDIUM` - 50-150 words
- `LONG` - 150-300 words

#### Response
```json
{
  "original_text": "Long article text...",
  "summary": "Concise summary of the key points...",
  "summary_type": "abstractive",
  "summary_length": "MEDIUM",
  "compression_ratio": 0.15,
  "key_sentences": [
    "Most important sentence from original.",
    "Another key point."
  ]
}
```

#### Example
```bash
curl -X POST "http://localhost:8000/summarize" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Long article text here...",
    "summary_type": "abstractive",
    "summary_length": "SHORT"
  }'
```

---

### 5. Batch Sentiment Analysis

**Endpoint**: `POST /batch/sentiment`  
**Rate Limit**: 20/min

#### Request Body
```json
{
  "texts": "array[string] (required, max 100 items)",
  "include_emotions": "boolean (optional, default: false)"
}
```

#### Response
```json
{
  "results": [
    {
      "text": "I love this!",
      "sentiment": "positive",
      "confidence": 0.95,
      "scores": {...}
    },
    {
      "text": "This is terrible.",
      "sentiment": "negative",
      "confidence": 0.92,
      "scores": {...}
    }
  ],
  "processed_count": 2,
  "failed_count": 0
}
```

#### Example
```bash
curl -X POST "http://localhost:8000/batch/sentiment" \
  -H "Content-Type: application/json" \
  -d '{
    "texts": [
      "I love this product!",
      "The service is terrible.",
      "It is okay, nothing special."
    ]
  }'
```

---

### 6. Batch Named Entity Recognition

**Endpoint**: `POST /batch/ner`  
**Rate Limit**: 20/min

#### Request Body
```json
{
  "texts": "array[string] (required, max 100 items)",
  "min_confidence": "float (optional, default: 0.5)"
}
```

#### Response
```json
{
  "results": [
    {
      "text": "Apple Inc. is in California.",
      "entities": [...],
      "entities_by_type": {...}
    },
    {
      "text": "Microsoft was founded by Bill Gates.",
      "entities": [...],
      "entities_by_type": {...}
    }
  ],
  "processed_count": 2,
  "failed_count": 0
}
```

---

### 7. Batch Summarization

**Endpoint**: `POST /batch/summarize`  
**Rate Limit**: 10/min

#### Request Body
```json
{
  "texts": "array[string] (required, max 50 items)",
  "summary_type": "string (optional, default: 'abstractive')",
  "summary_length": "string (optional, default: 'MEDIUM')"
}
```

#### Response
```json
{
  "results": [
    {
      "original_text": "Long text 1...",
      "summary": "Summary 1...",
      "compression_ratio": 0.15
    },
    {
      "original_text": "Long text 2...",
      "summary": "Summary 2...",
      "compression_ratio": 0.12
    }
  ],
  "processed_count": 2,
  "failed_count": 0
}
```

---

### 8. Health Check

**Endpoint**: `GET /health`  
**Rate Limit**: None

#### Response
```json
{
  "status": "healthy",
  "timestamp": "2025-10-12T14:30:00Z",
  "services": {
    "sentiment_analyzer": "operational",
    "entity_recognizer": "operational",
    "text_generator": "operational",
    "summarizer": "operational"
  },
  "version": "1.0.0"
}
```

---

### 9. WebSocket Statistics

**Endpoint**: `GET /ws/stats`  
**Rate Limit**: None

#### Response
```json
{
  "active_connections": 5,
  "total_connections": 127,
  "clients": {
    "client_123": {
      "messages_sent": 45,
      "messages_received": 43,
      "connected_at": "2025-10-12T14:25:00Z",
      "uptime_seconds": 300
    }
  }
}
```

---

## WebSocket Protocol

### Connection

**Endpoint**: `ws://localhost:8000/ws/{client_id}`

```javascript
const ws = new WebSocket('ws://localhost:8000/ws/my_client_id');

ws.onopen = () => {
  console.log('Connected');
};

ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  console.log('Received:', message);
};
```

### Message Types

#### 1. Welcome Message (Server → Client)
```json
{
  "type": "welcome",
  "client_id": "my_client_id",
  "timestamp": "2025-10-12T14:30:00Z",
  "message": "Connected to NLP WebSocket API"
}
```

#### 2. Task Request (Client → Server)
```json
{
  "task": "sentiment|generation|ner",
  "text": "Text to analyze",
  "options": {
    "include_emotions": true,
    "max_length": 100,
    "temperature": 0.7
  }
}
```

#### 3. Status Update (Server → Client)
```json
{
  "type": "status",
  "status": "processing",
  "task": "sentiment",
  "timestamp": "2025-10-12T14:30:01Z"
}
```

#### 4. Streaming Token (Server → Client)
```json
{
  "type": "token",
  "token": "The",
  "token_index": 0,
  "is_final": false
}
```

#### 5. Streaming Entity (Server → Client)
```json
{
  "type": "entity",
  "text": "Apple Inc.",
  "entity_type": "ORGANIZATION",
  "confidence": 0.95,
  "entity_index": 0,
  "total_entities": 3
}
```

#### 6. Result (Server → Client)
```json
{
  "type": "result",
  "task": "sentiment",
  "result": {
    "sentiment": "positive",
    "confidence": 0.95,
    "scores": {...}
  },
  "processing_time": 0.123
}
```

#### 7. Error (Server → Client)
```json
{
  "type": "error",
  "error": "Invalid task type",
  "task": "unknown",
  "timestamp": "2025-10-12T14:30:02Z"
}
```

#### 8. Ping/Pong (Keep-alive)
```json
// Client → Server
{
  "type": "ping"
}

// Server → Client
{
  "type": "pong",
  "timestamp": "2025-10-12T14:30:03Z"
}
```

#### 9. Stats Request (Client → Server)
```json
{
  "type": "stats"
}

// Response
{
  "type": "stats",
  "messages_sent": 45,
  "messages_received": 43,
  "uptime_seconds": 300
}
```

### WebSocket Examples

#### Sentiment Analysis (Streaming)
```python
import asyncio
import websockets
import json

async def sentiment_stream():
    uri = "ws://localhost:8000/ws/client_123"
    
    async with websockets.connect(uri) as websocket:
        # Send task
        await websocket.send(json.dumps({
            "task": "sentiment",
            "text": "I love WebSockets!",
            "options": {"include_emotions": true}
        }))
        
        # Receive responses
        async for message in websocket:
            data = json.loads(message)
            print(f"Received: {data['type']}")
            
            if data['type'] == 'result':
                print(f"Sentiment: {data['result']['sentiment']}")
                break

asyncio.run(sentiment_stream())
```

#### Text Generation (Token Streaming)
```javascript
const ws = new WebSocket('ws://localhost:8000/ws/client_123');

ws.onopen = () => {
  ws.send(JSON.stringify({
    task: 'generation',
    text: 'Once upon a time',
    options: {
      max_length: 100,
      temperature: 0.8
    }
  }));
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  
  if (data.type === 'token') {
    process.stdout.write(data.token + ' ');
  } else if (data.type === 'result') {
    console.log('\n\nGeneration complete!');
  }
};
```

#### NER (Entity Streaming)
```python
import asyncio
import websockets
import json

async def ner_stream():
    uri = "ws://localhost:8000/ws/client_456"
    
    async with websockets.connect(uri) as websocket:
        await websocket.send(json.dumps({
            "task": "ner",
            "text": "Apple was founded by Steve Jobs in Cupertino."
        }))
        
        entities = []
        async for message in websocket:
            data = json.loads(message)
            
            if data['type'] == 'entity':
                entities.append({
                    'text': data['text'],
                    'type': data['entity_type']
                })
                print(f"Found: {data['text']} ({data['entity_type']})")
            
            elif data['type'] == 'result':
                print(f"\nTotal entities: {len(entities)}")
                break

asyncio.run(ner_stream())
```

---

## Client Libraries

### Python Client

```python
import httpx
import asyncio

class NLPClient:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
        self.client = httpx.AsyncClient(timeout=60.0)
    
    async def sentiment(self, text, include_emotions=False):
        response = await self.client.post(
            f"{self.base_url}/sentiment",
            json={
                "text": text,
                "include_emotions": include_emotions
            }
        )
        return response.json()
    
    async def ner(self, text, min_confidence=0.5):
        response = await self.client.post(
            f"{self.base_url}/ner",
            json={
                "text": text,
                "min_confidence": min_confidence
            }
        )
        return response.json()
    
    async def generate(self, prompt, max_length=100, temperature=0.7):
        response = await self.client.post(
            f"{self.base_url}/generate",
            json={
                "prompt": prompt,
                "max_length": max_length,
                "temperature": temperature
            }
        )
        return response.json()
    
    async def summarize(self, text, summary_type="abstractive", 
                       summary_length="MEDIUM"):
        response = await self.client.post(
            f"{self.base_url}/summarize",
            json={
                "text": text,
                "summary_type": summary_type,
                "summary_length": summary_length
            }
        )
        return response.json()
    
    async def close(self):
        await self.client.aclose()

# Usage
async def main():
    client = NLPClient()
    
    # Sentiment analysis
    result = await client.sentiment("I love this!", include_emotions=True)
    print(f"Sentiment: {result['sentiment']}")
    
    # NER
    result = await client.ner("Apple was founded by Steve Jobs.")
    print(f"Entities: {result['entities_by_type']}")
    
    await client.close()

asyncio.run(main())
```

### JavaScript Client

```javascript
class NLPClient {
  constructor(baseURL = 'http://localhost:8000') {
    this.baseURL = baseURL;
  }

  async sentiment(text, includeEmotions = false) {
    const response = await fetch(`${this.baseURL}/sentiment`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, include_emotions: includeEmotions })
    });
    return response.json();
  }

  async ner(text, minConfidence = 0.5) {
    const response = await fetch(`${this.baseURL}/ner`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, min_confidence: minConfidence })
    });
    return response.json();
  }

  async generate(prompt, maxLength = 100, temperature = 0.7) {
    const response = await fetch(`${this.baseURL}/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt, max_length: maxLength, temperature })
    });
    return response.json();
  }

  async summarize(text, summaryType = 'abstractive', summaryLength = 'MEDIUM') {
    const response = await fetch(`${this.baseURL}/summarize`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        text, 
        summary_type: summaryType,
        summary_length: summaryLength
      })
    });
    return response.json();
  }
}

// Usage
const client = new NLPClient();

// Sentiment analysis
const sentiment = await client.sentiment('I love this!', true);
console.log('Sentiment:', sentiment.sentiment);

// NER
const ner = await client.ner('Apple was founded by Steve Jobs.');
console.log('Entities:', ner.entities_by_type);
```

---

## Performance Optimization Tips

### 1. Batch Processing
Use batch endpoints for multiple texts:
```python
# ❌ Slow (3 separate requests)
for text in texts:
    result = await client.sentiment(text)

# ✅ Fast (1 batch request)
results = await client.batch_sentiment(texts)
```

### 2. WebSocket for Real-time
Use WebSocket for streaming/interactive applications:
```python
# ❌ HTTP polling
while True:
    result = await client.generate(prompt)
    await asyncio.sleep(0.1)

# ✅ WebSocket streaming
async with websocket as ws:
    await ws.send({"task": "generation", "text": prompt})
    async for token in ws:
        print(token, end='')
```

### 3. Connection Pooling
Reuse HTTP connections:
```python
# ✅ Reuse client
client = NLPClient()
for text in texts:
    result = await client.sentiment(text)
await client.close()
```

### 4. Caching
Cache frequent requests:
```python
from functools import lru_cache

@lru_cache(maxsize=1000)
def get_sentiment(text):
    return client.sentiment(text)
```

---

**Last Updated**: October 12, 2025  
**API Version**: 1.0.0
