from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

RULES = [
    ("SQL Injection", ["or '1'='1", "union select", "select from", "' or 1=1"]),
    ("Cross-Site Scripting", ["<script", "javascript:", "onerror="]),
    ("Local File Inclusion", ["../", "..\\", "/etc/passwd"]),
    ("Command Injection", ["; ls", "&& cat", "| whoami"]),
]

THRESHOLD = 5
WINDOW_SECONDS = 60

state = {
    "events": deque(maxlen=50),
    "request_counts": defaultdict(list),
}


def reset_store():
    state["events"].clear()
    state["request_counts"].clear()


def detect_payload(payload: str) -> tuple[str, str]:
    lowered = payload.lower()
    for category, patterns in RULES:
        if any(pattern in lowered for pattern in patterns):
            return category, "blocked"
    if "<" in payload or "script" in lowered:
        return "Suspicious Input", "blocked"
    return "Benign", "allowed"


def check_rate_limit(ip: str) -> tuple[bool, str]:
    now = datetime.utcnow()
    timestamps = state["request_counts"].get(ip, [])
    recent = [ts for ts in timestamps if (now - ts).total_seconds() <= WINDOW_SECONDS]
    recent.append(now)
    state["request_counts"][ip] = recent
    if len(recent) >= THRESHOLD:
        return True, "rate_limited"
    return False, "allowed"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/submit", methods=["POST"])
def submit_request():
    payload_text = request.form.get("payload", "")
    target_url = request.form.get("target_url", "")
    method = request.form.get("method", "GET")
    ip = request.form.get("ip", "unknown")

    category, base_result = detect_payload(payload_text)
    rate_limited, rate_result = check_rate_limit(ip)
    if rate_limited:
        result = "rate_limited"
        category = "Suspicious Traffic"
    elif base_result == "blocked":
        result = "blocked"
    else:
        result = "allowed"

    event = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "target_url": target_url,
        "method": method,
        "category": category,
        "result": result,
    }
    state["events"].append(event)

    return jsonify({
        "message": f"Request processed with {result} status.",
        "result": result,
        "category": category,
        "event": event,
    })


@app.route("/dashboard")
def dashboard():
    blocked = sum(1 for event in state["events"] if event["result"] == "blocked")
    rate_limited = sum(1 for event in state["events"] if event["result"] == "rate_limited")
    categories = defaultdict(int)
    for event in state["events"]:
        categories[event["category"]] += 1
    return jsonify({
        "events": list(state["events"]),
        "summary": {
            "total": len(state["events"]),
            "blocked": blocked,
            "rate_limited": rate_limited,
            "categories": dict(categories),
        },
    })


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
