# quantum-lab/simulators/performance/resource_estimator.py

class ResourceEstimator:
    """
    Модуль оценки ресурсов квантового симулятора.
    Рассчитывает приблизительные затраты на выполнение квантового алгоритма,
    включая количество кубитов, глубину схемы и число используемых вентилей.
    """

    def __init__(self, circuit):
        """
        Инициализация с квантовой схемой (circuit).
        circuit должен содержать информацию о структуре схемы.
        """
        self.circuit = circuit

    def count_qubits(self):
        """
        Подсчет количества используемых кубитов в схеме.
        """
        return len(set(self.circuit.get_qubits()))

    def count_gates(self):
        """
        Подсчет общего количества вентилей в схеме.
        """
        return len(self.circuit.get_gates())

    def max_depth(self):
        """
        Оценка максимальной глубины схемы.
        """
        return self.circuit.get_depth()

    def estimate(self):
        """
        Возвращает словарь с ключевыми параметрами оценки ресурсов.
        """
        return {
            'qubits': self.count_qubits(),
            'gates': self.count_gates(),
            'depth': self.max_depth()
        }
