from fastapi.testclient import TestClient

from app.main import app


def test_health():
    client = TestClient(app)
    response = client.get('/health')
    assert response.status_code == 200


def test_create_token_api():
    client = TestClient(app)
    payload = {
        'name': 'Test User',
        'phone': '+971500000001',
        'department_id': 1,
        'language': 'EN'
    }
    response = client.post('/api/tokens', json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data['token_number'].startswith('ACC-')
