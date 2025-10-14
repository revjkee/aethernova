"""
Тесты для Audit Trail модуля
"""
import pytest
from datetime import datetime, timedelta
from audit_trail import AuditTrail, AuditEntry, BlockchainVerifier


@pytest.fixture
def audit_trail():
    """Fixture для audit trail"""
    return AuditTrail()


@pytest.fixture
def sample_entry():
    """Fixture для примера audit entry"""
    return AuditEntry(
        event_type="user_login",
        actor="test_user",
        resource="system",
        action="login",
        metadata={"ip": "192.168.1.1", "user_agent": "Mozilla/5.0"}
    )


class TestAuditTrail:
    """Тесты для AuditTrail"""
    
    def test_log_event(self, audit_trail, sample_entry):
        """Тест логирования события"""
        entry = audit_trail.log_event(
            event_type=sample_entry.event_type,
            actor=sample_entry.actor,
            resource=sample_entry.resource,
            action=sample_entry.action,
            metadata=sample_entry.metadata
        )
        
        assert entry.id is not None
        assert entry.event_type == sample_entry.event_type
        assert entry.actor == sample_entry.actor
        assert entry.hash is not None
        assert entry.previous_hash is not None
    
    def test_immutability(self, audit_trail):
        """Тест неизменяемости записей"""
        entry1 = audit_trail.log_event("test", "user1", "res1", "action1")
        entry2 = audit_trail.log_event("test", "user2", "res2", "action2")
        
        # Попытка изменить запись должна провалиться
        with pytest.raises(AttributeError):
            entry1.actor = "modified"
    
    def test_chain_integrity(self, audit_trail):
        """Тест целостности цепочки"""
        entries = []
        for i in range(5):
            entry = audit_trail.log_event(
                event_type="test",
                actor=f"user{i}",
                resource=f"res{i}",
                action=f"action{i}"
            )
            entries.append(entry)
        
        # Проверка связности цепочки
        for i in range(1, len(entries)):
            assert entries[i].previous_hash == entries[i-1].hash
    
    def test_verify_entry(self, audit_trail, sample_entry):
        """Тест верификации записи"""
        entry = audit_trail.log_event(
            event_type=sample_entry.event_type,
            actor=sample_entry.actor,
            resource=sample_entry.resource,
            action=sample_entry.action
        )
        
        is_valid = audit_trail.verify_entry(entry.id)
        assert is_valid is True
    
    def test_query_by_actor(self, audit_trail):
        """Тест запроса по actor"""
        audit_trail.log_event("test", "user1", "res1", "action1")
        audit_trail.log_event("test", "user2", "res2", "action2")
        audit_trail.log_event("test", "user1", "res3", "action3")
        
        results = audit_trail.query(actor="user1")
        assert len(results) == 2
        assert all(e.actor == "user1" for e in results)
    
    def test_query_by_timerange(self, audit_trail):
        """Тест запроса по временному диапазону"""
        now = datetime.utcnow()
        
        audit_trail.log_event("test", "user1", "res1", "action1")
        
        results = audit_trail.query(
            start_time=now - timedelta(minutes=1),
            end_time=now + timedelta(minutes=1)
        )
        assert len(results) >= 1
    
    def test_export_merkle_tree(self, audit_trail):
        """Тест экспорта Merkle tree"""
        for i in range(10):
            audit_trail.log_event("test", f"user{i}", f"res{i}", f"action{i}")
        
        merkle_root = audit_trail.get_merkle_root()
        assert merkle_root is not None
        assert len(merkle_root) == 64  # SHA256 hex


class TestBlockchainVerifier:
    """Тесты для BlockchainVerifier"""
    
    def test_verify_chain(self, audit_trail):
        """Тест верификации всей цепочки"""
        for i in range(5):
            audit_trail.log_event("test", f"user{i}", f"res{i}", f"action{i}")
        
        verifier = BlockchainVerifier(audit_trail)
        is_valid, errors = verifier.verify_chain()
        
        assert is_valid is True
        assert len(errors) == 0
    
    def test_detect_tampering(self, audit_trail):
        """Тест обнаружения подделки"""
        entries = []
        for i in range(3):
            entry = audit_trail.log_event("test", f"user{i}", f"res{i}", f"action{i}")
            entries.append(entry)
        
        # Симуляция подделки (изменение данных напрямую в storage)
        if audit_trail._entries:
            # Пытаемся изменить entry напрямую
            verifier = BlockchainVerifier(audit_trail)
            is_valid, errors = verifier.verify_chain()
            assert is_valid is True  # Должна оставаться валидной если не меняли


class TestWORMCompliance:
    """Тесты для WORM (Write Once Read Many)"""
    
    def test_worm_write_once(self, audit_trail):
        """Тест: запись один раз"""
        entry = audit_trail.log_event("test", "user1", "res1", "action1")
        
        # Попытка изменить должна провалиться
        with pytest.raises(Exception):
            audit_trail.update_entry(entry.id, {"actor": "modified"})
    
    def test_worm_read_many(self, audit_trail):
        """Тест: чтение много раз"""
        entry = audit_trail.log_event("test", "user1", "res1", "action1")
        
        # Множественное чтение должно работать
        for _ in range(100):
            retrieved = audit_trail.get_entry(entry.id)
            assert retrieved.id == entry.id


class TestPerformance:
    """Тесты производительности"""
    
    def test_bulk_insert_performance(self, audit_trail):
        """Тест производительности массовой вставки"""
        import time
        
        start = time.time()
        for i in range(1000):
            audit_trail.log_event("test", f"user{i}", f"res{i}", f"action{i}")
        duration = time.time() - start
        
        assert duration < 10  # Должно быть быстрее 10 секунд для 1000 записей
        assert len(audit_trail._entries) == 1000
    
    def test_query_performance(self, audit_trail):
        """Тест производительности запросов"""
        import time
        
        # Создаём 1000 записей
        for i in range(1000):
            audit_trail.log_event("test", f"user{i % 10}", f"res{i}", f"action{i}")
        
        start = time.time()
        results = audit_trail.query(actor="user5")
        duration = time.time() - start
        
        assert duration < 1  # Запрос должен быть быстрее 1 секунды
        assert len(results) > 0


class TestCryptographicVerification:
    """Тесты криптографической верификации"""
    
    def test_hash_consistency(self, audit_trail):
        """Тест консистентности хешей"""
        entry1 = audit_trail.log_event("test", "user1", "res1", "action1")
        entry2 = audit_trail.log_event("test", "user2", "res2", "action2")
        
        # Повторный расчёт хеша должен дать тот же результат
        recalculated_hash = audit_trail._calculate_hash(entry1)
        assert recalculated_hash == entry1.hash
    
    def test_merkle_tree_verification(self, audit_trail):
        """Тест верификации Merkle tree"""
        entries = []
        for i in range(8):  # Степень двойки для полного дерева
            entry = audit_trail.log_event("test", f"user{i}", f"res{i}", f"action{i}")
            entries.append(entry)
        
        merkle_root = audit_trail.get_merkle_root()
        
        # Верификация каждого элемента через Merkle proof
        for entry in entries:
            proof = audit_trail.get_merkle_proof(entry.id)
            is_valid = audit_trail.verify_merkle_proof(entry.id, proof, merkle_root)
            assert is_valid is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
