#!/usr/bin/env python3
"""
AetherNova NLP Supermodule - Test Client
Простой клиент для тестирования API
"""

import sys
import asyncio
import json
from pathlib import Path

# Добавление корневой директории в sys.path
root_dir = Path(__file__).parent.parent
sys.path.insert(0, str(root_dir))


def test_http_api():
    """Тестирование HTTP API"""
    import requests
    
    base_url = "http://localhost:8000"
    
    print("=" * 60)
    print("🧪 Testing HTTP API")
    print("=" * 60)
    
    # Health check
    print("\n1️⃣ Health Check")
    try:
        response = requests.get(f"{base_url}/health")
        print(f"✅ Status: {response.status_code}")
        print(f"📊 Response: {json.dumps(response.json(), indent=2)}")
    except Exception as e:
        print(f"❌ Error: {e}")
        return
    
    # Sentiment Analysis
    print("\n2️⃣ Sentiment Analysis")
    try:
        response = requests.post(
            f"{base_url}/sentiment",
            json={"text": "I absolutely love this product! It's amazing!", "include_emotions": True}
        )
        print(f"✅ Status: {response.status_code}")
        data = response.json()
        print(f"📊 Sentiment: {data['sentiment']} (confidence: {data['confidence']:.2f})")
        if 'emotions' in data and data['emotions']:
            print(f"😊 Emotions: {data['emotions']}")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # NER
    print("\n3️⃣ Named Entity Recognition")
    try:
        response = requests.post(
            f"{base_url}/ner",
            json={"text": "Apple Inc. was founded by Steve Jobs in Cupertino, California."}
        )
        print(f"✅ Status: {response.status_code}")
        data = response.json()
        print(f"📊 Found {data['entity_count']} entities:")
        for entity in data['entities'][:5]:  # Показываем первые 5
            print(f"   - {entity['text']} ({entity['entity_type']}): {entity['confidence']:.2f}")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Text Generation
    print("\n4️⃣ Text Generation")
    try:
        response = requests.post(
            f"{base_url}/generate",
            json={
                "prompt": "The future of AI is",
                "max_length": 50,
                "temperature": 0.7,
                "num_return_sequences": 2
            }
        )
        print(f"✅ Status: {response.status_code}")
        data = response.json()
        print(f"📊 Generated {len(data['generated_texts'])} variants:")
        for i, text in enumerate(data['generated_texts'], 1):
            print(f"   {i}. {text[:100]}...")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Summarization
    print("\n5️⃣ Text Summarization")
    try:
        long_text = """
        Artificial intelligence (AI) is intelligence demonstrated by machines, 
        as opposed to natural intelligence displayed by animals including humans. 
        AI research has been defined as the field of study of intelligent agents, 
        which refers to any system that perceives its environment and takes actions 
        that maximize its chance of achieving its goals. The term artificial intelligence 
        is often used to describe machines that mimic cognitive functions that humans 
        associate with the human mind, such as learning and problem solving.
        """
        response = requests.post(
            f"{base_url}/summarize",
            json={
                "text": long_text,
                "summary_length": "short",
                "summarization_type": "abstractive"
            }
        )
        print(f"✅ Status: {response.status_code}")
        data = response.json()
        print(f"📊 Summary: {data['summary']}")
        print(f"📏 Compression: {data['compression_ratio']:.1%}")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Batch Sentiment
    print("\n6️⃣ Batch Sentiment Analysis")
    try:
        response = requests.post(
            f"{base_url}/batch/sentiment",
            json={
                "texts": [
                    "I love this!",
                    "This is terrible.",
                    "It's okay."
                ]
            }
        )
        print(f"✅ Status: {response.status_code}")
        data = response.json()
        print(f"📊 Processed {data['count']} texts in {data['processing_time']:.3f}s:")
        for result in data['results']:
            print(f"   - {result['text'][:30]}: {result['sentiment']}")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    print("\n" + "=" * 60)
    print("✅ HTTP API tests completed!")
    print("=" * 60)


async def test_websocket_api():
    """Тестирование WebSocket API"""
    import websockets
    
    uri = "ws://localhost:8000/ws/test_client"
    
    print("\n" + "=" * 60)
    print("🧪 Testing WebSocket API")
    print("=" * 60)
    
    try:
        async with websockets.connect(uri) as websocket:
            # Welcome message
            print("\n1️⃣ Connecting...")
            welcome = await websocket.recv()
            welcome_data = json.loads(welcome)
            print(f"✅ Connected: {welcome_data['client_id']}")
            print(f"📋 Available tasks: {welcome_data['available_tasks']}")
            
            # Ping
            print("\n2️⃣ Ping")
            await websocket.send(json.dumps({"task": "ping"}))
            pong = await websocket.recv()
            pong_data = json.loads(pong)
            print(f"✅ Pong received: {pong_data['type']}")
            
            # Sentiment
            print("\n3️⃣ Sentiment Analysis")
            await websocket.send(json.dumps({
                "task": "sentiment",
                "text": "I love WebSockets!"
            }))
            status = await websocket.recv()
            print(f"📊 Status: {json.loads(status)['status']}")
            result = await websocket.recv()
            result_data = json.loads(result)
            print(f"✅ Result: {result_data['data']['sentiment']}")
            
            # NER
            print("\n4️⃣ Named Entity Recognition")
            await websocket.send(json.dumps({
                "task": "ner",
                "text": "Apple Inc. in California"
            }))
            status = await websocket.recv()
            result = await websocket.recv()
            result_data = json.loads(result)
            print(f"✅ Found {len(result_data['data']['entities'])} entities")
            
            # Generation
            print("\n5️⃣ Text Generation")
            await websocket.send(json.dumps({
                "task": "generation",
                "prompt": "The future is",
                "max_length": 30
            }))
            status = await websocket.recv()
            result = await websocket.recv()
            result_data = json.loads(result)
            print(f"✅ Generated text: {result_data['data']['generated_texts'][0][:50]}...")
            
            # Summarize
            print("\n6️⃣ Summarization")
            await websocket.send(json.dumps({
                "task": "summarize",
                "text": "AI is transforming the world. " * 20,
                "summary_length": "short"
            }))
            status = await websocket.recv()
            result = await websocket.recv()
            result_data = json.loads(result)
            print(f"✅ Summary: {result_data['data']['summary'][:50]}...")
            
            # Batch Sentiment
            print("\n7️⃣ Batch Sentiment")
            await websocket.send(json.dumps({
                "task": "batch",
                "subtask": "sentiment",
                "texts": ["Love it!", "Hate it.", "It's okay."]
            }))
            result = await websocket.recv()
            result_data = json.loads(result)
            print(f"✅ Processed {len(result_data['data'])} texts")
            
            print("\n" + "=" * 60)
            print("✅ WebSocket API tests completed!")
            print("=" * 60)
            
    except Exception as e:
        print(f"❌ WebSocket error: {e}")
        print("💡 Make sure the server is running: python api/run_server.py")


def main():
    """Главная функция"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Test NLP API")
    parser.add_argument(
        "--mode",
        choices=["http", "ws", "all"],
        default="all",
        help="Test mode (default: all)"
    )
    
    args = parser.parse_args()
    
    print("🚀 AetherNova NLP Supermodule - API Test Client")
    
    try:
        if args.mode in ["http", "all"]:
            test_http_api()
        
        if args.mode in ["ws", "all"]:
            asyncio.run(test_websocket_api())
    
    except KeyboardInterrupt:
        print("\n\n👋 Tests interrupted by user")
    except Exception as e:
        print(f"\n❌ Test error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
