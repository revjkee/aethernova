import logging
from typing import List, Dict

class DefenseLayer:
    """
    Абстрактный класс слоя защиты.
    Каждый слой реализует методы и политики для предотвращения угроз.
    """
    def __init__(self, name: str):
        self.name = name
        self.logger = logging.getLogger(f"DefenseLayer.{name}")
        self.logger.setLevel(logging.INFO)

    def detect(self, event: Dict) -> bool:
        """
        Метод обнаружения атаки/угрозы.
        Возвращает True, если угроза выявлена.
        """
        raise NotImplementedError

    def respond(self, event: Dict) -> None:
        """
        Метод реакции на обнаруженную угрозу.
        """
        raise NotImplementedError

    def status(self) -> str:
        """
        Возвращает статус слоя защиты.
        """
        return f"Layer {self.name} is operational."


class FirewallLayer(DefenseLayer):
    def __init__(self):
        super().__init__("Firewall")

    def detect(self, event: Dict) -> bool:
        if event.get("type") == "network" and event.get("threat_level", 0) > 5:
            self.logger.info("Firewall detected high threat network event.")
            return True
        return False

    def respond(self, event: Dict) -> None:
        self.logger.info(f"Firewall blocking IP: {event.get('source_ip')}")


class AntivirusLayer(DefenseLayer):
    def __init__(self):
        super().__init__("Antivirus")

    def detect(self, event: Dict) -> bool:
        if event.get("type") == "file" and event.get("signature_match", False):
            self.logger.info("Antivirus detected malicious file.")
            return True
        return False

    def respond(self, event: Dict) -> None:
        self.logger.info(f"Antivirus quarantined file: {event.get('file_path')}")


class BehaviorAnalysisLayer(DefenseLayer):
    def __init__(self):
        super().__init__("BehaviorAnalysis")

    def detect(self, event: Dict) -> bool:
        if event.get("type") == "behavior" and event.get("anomaly_score", 0) > 70:
            self.logger.info("BehaviorAnalysis detected suspicious activity.")
            return True
        return False

    def respond(self, event: Dict) -> None:
        self.logger.info(f"BehaviorAnalysis triggered alert for user: {event.get('user_id')}")


class DefenseInDepth:
    """
    Менеджер многослойной защиты.
    Инициирует и координирует работу слоев защиты.
    """

    def __init__(self, layers: List[DefenseLayer]):
        self.layers = layers
        self.logger = logging.getLogger("DefenseInDepth")
        self.logger.setLevel(logging.INFO)

    def analyze_event(self, event: Dict) -> None:
        """
        Проверяет событие через все слои защиты и инициирует реакции.
        """
        self.logger.info(f"Analyzing event: {event}")
        for layer in self.layers:
            if layer.detect(event):
                layer.respond(event)
                # Можно остановить дальнейшую обработку, если угроза устранена
                break

    def system_status(self) -> Dict[str, str]:
        """
        Возвращает статус каждого слоя защиты.
        """
        status_report = {}
        for layer in self.layers:
            status_report[layer.name] = layer.status()
        return status_report
