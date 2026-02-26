from fastapi.testclient import TestClient

from app.main import app


def test_health():
    with TestClient(app) as client:
        response = client.get('/health')
    assert response.status_code == 200


def test_create_token_api():
    with TestClient(app) as client:
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


def test_admin_reports_requires_auth():
    with TestClient(app) as client:
        response = client.get('/admin/reports')
    assert response.status_code == 401


def test_admin_reports_page_renders_for_admin():
    with TestClient(app) as client:
        login = client.post('/login', data={'username': 'admin', 'password': 'admin123'}, follow_redirects=False)
        assert login.status_code == 303
        response = client.get('/admin/reports')
    assert response.status_code == 200
    assert 'Reports &amp; Evaluation' in response.text
