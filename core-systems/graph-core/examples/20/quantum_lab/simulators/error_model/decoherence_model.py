# quantum-lab/simulators/error_model/decoherence_model.py

import numpy as np

class DecoherenceModel:
    """
    Модель декогеренции для квантовых систем.
    Симулирует эффекты потери когерентности T1 и T2, а также дефазировки.
    """

    def __init__(self, t1: float, t2: float, dt: float):
        """
        Инициализация модели.
        t1 - время релаксации (в наносекундах)
        t2 - время дефазировки (в наносекундах)
        dt - временной шаг симуляции (в наносекундах)
        """
        self.t1 = t1
        self.t2 = t2
        self.dt = dt

        # Коэффициенты вероятности ошибок за один шаг
        self.p_relax = 1 - np.exp(-dt / t1) if t1 > 0 else 0
        self.p_dephase = 1 - np.exp(-dt / t2) if t2 > 0 else 0

    def apply(self, rho: np.ndarray) -> np.ndarray:
        """
        Применение модели декогеренции к матрице плотности rho.
        Используется операторная форма Крауса для аппроксимации релаксации и дефазировки.
        """

        # Операторы Крауса для релаксации T1
        K0 = np.array([[1, 0],
                       [0, np.sqrt(1 - self.p_relax)]], dtype=complex)
        K1 = np.array([[0, np.sqrt(self.p_relax)],
                       [0, 0]], dtype=complex)

        # Операторы Крауса для дефазировки T2 (здесь учтено, что T2 ≤ 2*T1)
        p_phi = self.p_dephase - self.p_relax / 2
        p_phi = max(p_phi, 0)
        K2 = np.sqrt(1 - p_phi) * np.eye(2, dtype=complex)
        K3 = np.sqrt(p_phi) * np.array([[1, 0], [0, -1]], dtype=complex)

        # Применение операторов последовательно
        rho_new = np.zeros_like(rho, dtype=complex)

        for K in [K0, K1, K2, K3]:
            rho_new += K @ rho @ K.conj().T

        return rho_new
