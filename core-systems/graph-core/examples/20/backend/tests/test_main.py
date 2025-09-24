# backend/tests/test_main.py

import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Welcome to TeslaAI Backend"}

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_invalid_route():
    response = client.get("/invalid-route")
    assert response.status_code == 404

def test_api_auth_required():
    response = client.get("/api/protected-resource")
    assert response.status_code == 401

def test_api_protected_resource_with_token():
    token = "valid_test_token"  # Предполагается, что в тестах есть мок авторизации
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/protected-resource", headers=headers)
    assert response.status_code == 200
    assert "data" in response.json()

if __name__ == "__main__":
    pytest.main()
