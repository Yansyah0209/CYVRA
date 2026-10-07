"""Verify the running Docker Compose stack through its frontend proxy."""

import json
import time
import urllib.request


def request(path, data=None):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(
        "http://127.0.0.1:3000/api" + path,
        data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)


def main():
    for _ in range(120):
        try:
            request("/projects")
            break
        except OSError:
            time.sleep(0.5)
    else:
        raise RuntimeError("Compose frontend/backend/database were not ready within 60s")
    project = request("/projects", {"name": "Compose integration"})["id"]
    route = "/projects/" + project
    request(route + "/demo", {})
    analysis = request(route + "/analysis")
    assert analysis["summary"]["findings"] == 7
    result = request(route + "/simulate", {"actions": [{"kind": "segment", "target_id": "api"}]})
    assert result["after"]["summary"]["paths"] == 0
    assert request(route + "/dataset")["findings"][0]["status"] == "open"
    assert request(route + "/explain", {"question": "Why is risk high?"})["citations"]
    print(json.dumps({"compose": "passed", "summary": analysis["summary"]}, indent=2))


if __name__ == "__main__":
    main()
