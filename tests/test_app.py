import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app, reset_store


def test_sqli_detection():
    reset_store()
    client = app.test_client()
    response = client.post(
        "/submit",
        data={
            "target_url": "http://example.test/login",
            "method": "GET",
            "payload": "admin' OR '1'='1",
            "ip": "203.0.113.10",
        },
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["result"] == "blocked"
    assert payload["category"] == "SQL Injection"


def test_rate_limiting_detects_abuse():
    reset_store()
    client = app.test_client()
    for idx in range(7):
        client.post(
            "/submit",
            data={
                "target_url": "http://example.test/login",
                "method": "POST",
                "payload": f"test-{idx}",
                "ip": "198.51.100.77",
            },
        )
    response = client.post(
        "/submit",
        data={
            "target_url": "http://example.test/login",
            "method": "POST",
            "payload": "final-test",
            "ip": "198.51.100.77",
        },
    )
    payload = response.get_json()
    assert payload["result"] == "rate_limited"
    assert payload["category"] == "Suspicious Traffic"
