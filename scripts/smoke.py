"""Run an actual built frontend proxy and API together, and verify the full REST flow."""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as temp:
    env = {
        **os.environ,
        "DATABASE_URL": "sqlite:///" + str(Path(temp) / "smoke.db"),
        "CYVRA_API_KEY": "smoke-only",
        "HOSTNAME": "127.0.0.1",
    }
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=root / "backend", env=env, check=True)
    servers = [
        subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"],
            cwd=root / "backend",
            env=env,
            stdout=subprocess.DEVNULL,
        ),
        subprocess.Popen(["node", "scripts/start.mjs"], cwd=root / "frontend", env=env, stdout=subprocess.DEVNULL),
    ]

    def request(path, data=None):
        body = json.dumps(data).encode() if data is not None else None
        req = urllib.request.Request(
            "http://127.0.0.1:3000/api" + path, data=body, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=60) as response:
            return json.load(response)

    try:
        for _ in range(100):
            try:
                request("/projects")
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("Servers did not start")
        project = request("/projects", {"name": "smoke"})["id"]
        route = "/projects/" + project
        request(route + "/demo", {})
        analysis = request(route + "/analysis")
        assert analysis["summary"]["findings"] == 7
        rec = request(route + "/recommendations", {"budget": 3})
        assert rec["cost"] <= 3
        simulation = request(route + "/simulate", {"actions": [{"kind": "segment", "target_id": "api"}]})
        assert simulation["after"]["summary"]["paths"] == 0
        assert request(route + "/dataset")["findings"][0]["status"] == "open"
        assert request(route + "/explain", {"question": "What should I fix first?"})["citations"]
        print(
            json.dumps(
                {
                    "status": "passed",
                    "summary": analysis["summary"],
                    "risk": analysis["risk"],
                    "simulation": simulation["after"],
                },
                indent=2,
            )
        )
    finally:
        for server in servers:
            server.terminate()
        for server in servers:
            server.wait(timeout=10)
