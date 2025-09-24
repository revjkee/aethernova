import requests

class AIClientAPI:
    def __init__(self, api_key: str, endpoint: str):
        self.api_key = api_key
        self.endpoint = endpoint

    def send_request(self, prompt: str) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "model": "gpt-4o-mini",
            "prompt": prompt,
            "max_tokens": 150,
            "temperature": 0.7
        }
        response = requests.post(self.endpoint, json=data, headers=headers)
        response.raise_for_status()
        return response.json()['choices'][0]['text'].strip()
