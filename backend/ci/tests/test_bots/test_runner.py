import asyncio
import logging
from typing import List, Callable, Awaitable

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

class TestRunner:
    def __init__(self):
        self.tests: List[Callable[[], Awaitable[bool]]] = []

    def add_test(self, test_func: Callable[[], Awaitable[bool]]) -> None:
        """
        Добавляет асинхронную тестовую функцию в список.
        Тестовая функция должна возвращать bool (True - успешно, False - провал).
        """
        self.tests.append(test_func)
        logger.debug(f"Добавлен тест: {test_func.__name__}")

    async def run_all(self) -> bool:
        """
        Асинхронно запускает все тесты последовательно.
        Возвращает True, если все тесты прошли успешно, иначе False.
        """
        logger.info("Запуск всех тестов")
        all_passed = True
        for test in self.tests:
            try:
                result = await test()
                if result:
                    logger.info(f"Тест {test.__name__} пройден успешно")
                else:
                    logger.error(f"Тест {test.__name__} завершился с ошибкой")
                    all_passed = False
            except Exception as e:
                logger.error(f"Ошибка при выполнении теста {test.__name__}: {e}")
                all_passed = False
        logger.info(f"Все тесты завершены. Итог: {'УСПЕХ' if all_passed else 'НЕУСПЕХ'}")
        return all_passed


# Пример асинхронного теста
async def sample_test_success() -> bool:
    await asyncio.sleep(0.1)  # эмуляция асинхронной работы
    return True

async def sample_test_failure() -> bool:
    await asyncio.sleep(0.1)
    return False


if __name__ == "__main__":
    async def main():
        runner = TestRunner()
        runner.add_test(sample_test_success)
        runner.add_test(sample_test_failure)
        success = await runner.run_all()
        exit(0 if success else 1)

    asyncio.run(main())
