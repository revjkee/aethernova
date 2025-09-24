import pytest
import os
import tempfile
import logging
from unittest.mock import patch, MagicMock
from keyvault.core.audit_logger import AuditLogger


@pytest.fixture
def temp_log_file():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    yield path
    os.remove(path)


def test_logger_initialization(temp_log_file):
    logger = AuditLogger(log_file=temp_log_file)
    assert logger.logger.name == "AuditLogger"
    assert isinstance(logger.logger.handlers[0], logging.FileHandler)


def test_log_action_format(temp_log_file):
    logger = AuditLogger(log_file=temp_log_file)
    logger.log_action(user="test_user", action="TEST_ACTION", status="SUCCESS", metadata={"ip": "127.0.0.1"})

    with open(temp_log_file, "r") as f:
        log_line = f.readline()
        assert "test_user" in log_line
        assert "TEST_ACTION" in log_line
        assert "SUCCESS" in log_line
        assert "ip=127.0.0.1" in log_line


def test_log_injection_safety(temp_log_file):
    malicious_input = "injected\nCRITICAL:root:exploit"
    logger = AuditLogger(log_file=temp_log_file)
    logger.log_action(user=malicious_input, action="TEST", status="OK")

    with open(temp_log_file, "r") as f:
        lines = f.readlines()
        assert len(lines) == 1
        assert "injected" in lines[0]
        assert "CRITICAL" not in lines[0]  # log injection protection


def test_logging_multiple_entries(temp_log_file):
    logger = AuditLogger(log_file=temp_log_file)
    for i in range(5):
        logger.log_action(user=f"user{i}", action="ACTION", status="OK")
    
    with open(temp_log_file, "r") as f:
        lines = f.readlines()
        assert len(lines) == 5
        assert "user3" in lines[3]


def test_custom_metadata_logging(temp_log_file):
    logger = AuditLogger(log_file=temp_log_file)
    metadata = {"ip": "192.168.0.2", "device": "macbook"}
    logger.log_action(user="meta_user", action="META_ACTION", status="OK", metadata=metadata)

    with open(temp_log_file, "r") as f:
        content = f.read()
        assert "ip=192.168.0.2" in content
        assert "device=macbook" in content


def test_logger_with_mock_handler():
    with patch("keyvault.core.audit_logger.logging.FileHandler") as mock_handler:
        logger = AuditLogger(log_file="/fake/path.log")
        logger.log_action(user="tester", action="MOCK", status="OK")
        assert mock_handler.called
        assert logger.logger.name == "AuditLogger"


def test_timestamp_format(temp_log_file):
    logger = AuditLogger(log_file=temp_log_file)
    logger.log_action(user="time_user", action="TIME_CHECK", status="OK")
    
    with open(temp_log_file, "r") as f:
        line = f.readline()
        import re
        match = re.match(r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]", line)
        assert match is not None


def test_invalid_metadata_handling(temp_log_file):
    logger = AuditLogger(log_file=temp_log_file)
    logger.log_action(user="test", action="INVALID_META", status="WARN", metadata="not_a_dict")

    with open(temp_log_file, "r") as f:
        log_line = f.readline()
        assert "metadata=INVALID" in log_line or "not_a_dict" not in log_line


def test_log_rotation_strategy(temp_log_file):
    # Допустим у нас используется logrotate или другой механизм — имитация
    logger = AuditLogger(log_file=temp_log_file)
    logger.log_action(user="rotate_user", action="ROTATE", status="PRE")

    os.rename(temp_log_file, temp_log_file + ".1")
    open(temp_log_file, "w").close()  # create new empty

    logger.log_action(user="rotate_user", action="ROTATE", status="POST")

    with open(temp_log_file, "r") as f:
        lines = f.readlines()
        assert "ROTATE" in lines[0]
