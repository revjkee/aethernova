import time
from typing import Dict, List

class ScoringAPI:
    """
    Высокопроизводительный API для подсчёта очков CTF.
    Поддерживает обновление очков, получение рейтингов и
    предотвращение мошенничества.
    """

    def __init__(self):
        # Хранилище результатов: {user_id: {challenge_id: score}}
        self.scores: Dict[str, Dict[str, int]] = {}
        # Таймстампы для предотвращения повторных начислений
        self.last_submission_time: Dict[str, float] = {}

        # Минимальный интервал между сабмитами, сек
        self.min_interval = 10

    def submit_score(self, user_id: str, challenge_id: str, score: int) -> bool:
        """
        Попытка засчитать очки пользователю.
        Возвращает True, если засчитано, False при подозрении на мошенничество.
        """
        now = time.time()
        key = f"{user_id}:{challenge_id}"

        last_time = self.last_submission_time.get(key, 0)
        if now - last_time < self.min_interval:
            # Повторная отправка слишком быстро
            return False

        self.last_submission_time[key] = now

        if user_id not in self.scores:
            self.scores[user_id] = {}

        current_score = self.scores[user_id].get(challenge_id, 0)
        if score > current_score:
            self.scores[user_id][challenge_id] = score
        return True

    def get_total_score(self, user_id: str) -> int:
        """
        Возвращает сумму очков пользователя по всем задачам.
        """
        return sum(self.scores.get(user_id, {}).values())

    def get_leaderboard(self, top_n: int = 10) -> List[Dict[str, int]]:
        """
        Возвращает топ пользователей по суммарным очкам.
        Формат: [{"user_id": str, "score": int}, ...]
        """
        leaderboard = [
            {"user_id": uid, "score": self.get_total_score(uid)}
            for uid in self.scores.keys()
        ]
        leaderboard.sort(key=lambda x: x["score"], reverse=True)
        return leaderboard[:top_n]

# Пример использования
if __name__ == "__main__":
    api = ScoringAPI()
    assert api.submit_score("user1", "chal1", 100) is True
    assert api.submit_score("user1", "chal1", 90) is True  # Не понизит очки
    assert api.submit_score("user1", "chal1", 110) is True
    print("User1 total:", api.get_total_score("user1"))
    print("Leaderboard:", api.get_leaderboard())
