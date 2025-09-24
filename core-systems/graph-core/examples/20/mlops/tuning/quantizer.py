import torch
import torch.nn as nn

class Quantizer:
    """
    Модуль для пост-тренировочного квантования тензоров модели.
    Поддерживает квантование с понижением разрядности до int8 и ниже для уменьшения памяти и ускорения инференса.
    """

    def __init__(self, num_bits: int = 8):
        assert num_bits in (8, 4), "Поддерживается только 8- или 4-битное квантование"
        self.num_bits = num_bits
        self.qmin = 0
        self.qmax = 2 ** num_bits - 1

    def quantize_tensor(self, x: torch.Tensor) -> torch.Tensor:
        """
        Квантование входного тензора x с масштабированием и смещением.
        Возвращает квантизованный тензор в формате int и параметры scale, zero_point для обратного восстановления.
        """
        x_min = x.min()
        x_max = x.max()

        scale = (x_max - x_min) / (self.qmax - self.qmin)
        zero_point = self.qmin - x_min / scale
        zero_point = zero_point.clamp(self.qmin, self.qmax).round()

        q_x = (x / scale + zero_point).round().clamp(self.qmin, self.qmax).to(torch.uint8)
        return q_x, scale, zero_point

    def dequantize_tensor(self, q_x: torch.Tensor, scale: float, zero_point: float) -> torch.Tensor:
        """
        Обратное преобразование квантованного тензора в float32.
        """
        return scale * (q_x.float() - zero_point)

