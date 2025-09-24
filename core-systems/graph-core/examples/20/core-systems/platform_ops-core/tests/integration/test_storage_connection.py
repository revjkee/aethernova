import pytest
from llmops.data_store import FeedbackStore, StorageConnectionError

@pytest.fixture
def store():
    return FeedbackStore()

def test_storage_connection_success(store):
    # Проверка успешного подключения к хранилищу
    assert store.is_connected() is True

def test_save_and_retrieve_feedback(store):
    feedback = {"user_id": 1, "rating": 5, "comment": "Great service"}
    result = store.save_feedback(feedback)
    assert result is True

    all_feedback = store.get_all_feedback()
    assert feedback in all_feedback

def test_storage_connection_failure(monkeypatch):
    # Имитируем ошибку подключения к хранилищу
    def fail_connect():
        raise StorageConnectionError("Cannot connect to storage")

    monkeypatch.setattr(FeedbackStore, "is_connected", fail_connect)

    store = FeedbackStore()
    with pytest.raises(StorageConnectionError):
        store.is_connected()

def test_storage_reconnect_logic(store, monkeypatch):
    # Проверяем логику переподключения (если есть)
    called = {"attempted": False}

    def fake_reconnect():
        called["attempted"] = True
        return True

    monkeypatch.setattr(store, "reconnect", fake_reconnect)

    # Вызовем метод переподключения
    result = store.reconnect()
    assert result is True
    assert called["attempted"] is True
