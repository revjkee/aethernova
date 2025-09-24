from ai_client import AIClientAPI

class DevelopmentAgent01:
    def __init__(self, ai_client):
        self.ai_client = ai_client
        self.name = "DevelopmentAgent01"

    def initialize(self):
        print(f"[{self.name}] Инициализация.")

    def run(self):
        prompt = "Опиши архитектуру проекта TeslaAI кратко и по делу."
        print(f"[{self.name}] Запрос к ИИ: {prompt}")
        response = self.ai_client.send_request(prompt)
        print(f"[{self.name}] Ответ ИИ:\n{response}")

    def shutdown(self):
        print(f"[{self.name}] Завершение работы.")

def main():
    api_key = "ВАШ_API_КЛЮЧ"
    endpoint = "https://api.openai.com/v1/chat/completions"  # или нужный вам URL

    ai_client = AIClientAPI(api_key, endpoint)
    agent = DevelopmentAgent01(ai_client)

    agent.initialize()
    agent.run()
    agent.shutdown()

if __name__ == "__main__":
    main()
