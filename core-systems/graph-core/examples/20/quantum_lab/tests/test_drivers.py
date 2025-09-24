# quantum-lab/tests/test_drivers.py

import unittest
from quantum_lab.drivers import QuantumDeviceDriver, DriverConnectionError

class TestQuantumDeviceDriver(unittest.TestCase):
    """
    Тестирование драйвера для управления квантовым устройством.
    Проверяется инициализация, подключение, отправка команд и обработка ошибок.
    """

    def setUp(self):
        self.driver = QuantumDeviceDriver(device_id="quantum01")

    def test_driver_initialization(self):
        self.assertEqual(self.driver.device_id, "quantum01")
        self.assertFalse(self.driver.is_connected())

    def test_driver_connection(self):
        self.driver.connect()
        self.assertTrue(self.driver.is_connected())

    def test_driver_command_send(self):
        self.driver.connect()
        response = self.driver.send_command("INIT")
        self.assertEqual(response.status, "OK")

    def test_driver_error_on_send_without_connection(self):
        with self.assertRaises(DriverConnectionError):
            self.driver.send_command("INIT")

if __name__ == "__main__":
    unittest.main()
