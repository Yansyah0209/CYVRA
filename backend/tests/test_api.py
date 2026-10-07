import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.main import app
from app.db import Base, session


@pytest.fixture
def client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)

    def override():
        with factory() as db:
            yield db

    app.dependency_overrides[session] = override
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
    engine.dispose()


def test_complete_workflow(client, data):
    p = client.post("/api/projects", json={"name": "test"})
    assert p.status_code == 201
    route = "/api/projects/" + p.json()["id"]
    assert client.get(route + "/analysis").status_code == 409
    assert client.post(route + "/import", json=data.model_dump(mode="json")).status_code == 200
    assert client.get(route + "/analysis").json()["summary"]["findings"] == 7
    assert client.post(route + "/recommendations", json={"budget": 2}).status_code == 200
    assert (
        client.post(route + "/simulate", json={"actions": [{"kind": "segment", "target_id": "api"}]}).json()["after"][
            "summary"
        ]["paths"]
        == 0
    )
    assert client.get(route + "/dataset").json() == data.model_dump(mode="json")
    response = client.post(route + "/explain", json={"question": "What should I fix first?"}).json()
    assert response["provider"] == "offline-structured" and response["citations"]


def test_demo_and_errors(client):
    p = client.post("/api/projects", json={"name": "demo"}).json()["id"]
    assert client.post(f"/api/projects/{p}/demo").status_code == 200
    assert client.get("/api/projects/missing/analysis").status_code == 404
    assert (
        client.post(
            f"/api/projects/{p}/simulate", json={"actions": [{"kind": "patch", "target_id": "missing"}]}
        ).status_code
        == 422
    )
    assert client.post("/api/projects", json={"name": ""}).status_code == 422
    assert client.post(f"/api/projects/{p}/simulate", json={"actions": []}).status_code == 422


def test_optional_api_key(client, monkeypatch):
    monkeypatch.setenv("CYVRA_API_KEY", "test-secret")
    assert client.get("/api/projects").status_code == 401
    assert client.get("/api/projects", headers={"x-api-key": "test-secret"}).status_code == 200
    assert client.get("/health").status_code == 200


def test_request_limit(client):
    assert client.post("/api/projects", content="x" * 2_000_001).status_code == 413


def test_demo_in_container_layout(client, data, tmp_path, monkeypatch):
    import json
    from app import main

    app_dir = tmp_path / "app"
    app_dir.mkdir()
    fixture = tmp_path / "datasets/synthetic/aurora.json"
    fixture.parent.mkdir(parents=True)
    fixture.write_text(json.dumps(data.model_dump(mode="json")))
    monkeypatch.setattr(main, "__file__", str(app_dir / "main.py"))
    project = client.post("/api/projects", json={"name": "container layout"}).json()["id"]
    assert client.post(f"/api/projects/{project}/demo").status_code == 200
    assert client.get(f"/api/projects/{project}/analysis").json()["summary"]["findings"] == 7


def test_demo_missing_configuration(client, monkeypatch, tmp_path):
    monkeypatch.setenv("DEMO_DATA_PATH", str(tmp_path / "absent.json"))
    project = client.post("/api/projects", json={"name": "missing fixture"}).json()["id"]
    assert client.post(f"/api/projects/{project}/demo").status_code == 503
