import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
from gateway.main import app
from gateway.zk.verifier import verify_proof
from pydantic import BaseModel


client = TestClient(app)


class ZKProofInput(BaseModel):
    proof: dict
    publicSignals: list


valid_proof_input = {
    "proof": {
        "pi_a": ["0x1", "0x2"],
        "pi_b": [["0x3", "0x4"], ["0x5", "0x6"]],
        "pi_c": ["0x7", "0x8"]
    },
    "publicSignals": ["1"]
}

invalid_proof_input = {
    "proof": {
        "pi_a": ["0x0", "0x0"],
        "pi_b": [["0x0", "0x0"], ["0x0", "0x0"]],
        "pi_c": ["0x0", "0x0"]
    },
    "publicSignals": ["0"]
}


@pytest.fixture
def proof_data_valid():
    return ZKProofInput(**valid_proof_input)


@pytest.fixture
def proof_data_invalid():
    return ZKProofInput(**invalid_proof_input)


def test_zk_verifier_valid(monkeypatch, proof_data_valid):
    monkeypatch.setattr("gateway.zk.verifier.verify_proof", lambda p, s: True)
    response = client.post("/api/zk/verify", json=valid_proof_input)
    assert response.status_code == 200
    assert response.json() == {"verified": True}


def test_zk_verifier_invalid(monkeypatch, proof_data_invalid):
    monkeypatch.setattr("gateway.zk.verifier.verify_proof", lambda p, s: False)
    response = client.post("/api/zk/verify", json=invalid_proof_input)
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid ZK proof"


def test_verify_proof_logic_true():
    with patch("gateway.zk.verifier.groth16.verify", return_value=True):
        result = verify_proof(valid_proof_input["proof"], valid_proof_input["publicSignals"])
        assert result is True


def test_verify_proof_logic_false():
    with patch("gateway.zk.verifier.groth16.verify", return_value=False):
        result = verify_proof(valid_proof_input["proof"], valid_proof_input["publicSignals"])
        assert result is False


def test_zk_endpoint_missing_field():
    incomplete_data = {
        "proof": valid_proof_input["proof"]
        # publicSignals отсутствует
    }
    response = client.post("/api/zk/verify", json=incomplete_data)
    assert response.status_code == 422  # Unprocessable Entity


def test_zk_endpoint_invalid_format():
    malformed = {
        "proof": "not_a_dict",
        "publicSignals": "not_a_list"
    }
    response = client.post("/api/zk/verify", json=malformed)
    assert response.status_code == 422


def test_zk_endpoint_empty_proof():
    empty_input = {
        "proof": {"pi_a": [], "pi_b": [[], []], "pi_c": []},
        "publicSignals": []
    }
    response = client.post("/api/zk/verify", json=empty_input)
    assert response.status_code in [400, 422]
