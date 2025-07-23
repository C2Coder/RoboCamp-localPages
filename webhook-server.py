
from __future__ import annotations

import os
import sys
import hmac
import hashlib
import logging
import threading
import queue
from typing import Any, Callable, Dict
import argparse
import yaml
from flask import Flask, request, abort, jsonify
from dotenv import load_dotenv
import signal
CONFIG_FILE = "webhook-config.yaml"

# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict:
    cfg = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            user_cfg = yaml.safe_load(f) or {}
        for k, v in user_cfg.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k].update(v)
            else:
                cfg[k] = v
        return cfg
    except Exception as exc:
        print(f"Failed to load config {path}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

load_dotenv()  # take environment variables
CFG = load_config(CONFIG_FILE)
GITHUB_WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", CFG["webhook"].get("secret", ""))
ALLOW_EMPTY_SECRET_FOR_PING = bool(CFG["webhook"].get("allow_empty_secret_for_ping", False))
MAX_CONTENT_LENGTH = int(CFG["server"].get("max_content_length", 5 * 1024 * 1024))
HOST = str(CFG["server"].get("host", "0.0.0.0"))
PORT = int(CFG["server"].get("port", 7070))

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------

def verify_github_signature(raw_body: bytes, headers: Dict[str, str]) -> bool:
    sig_header = headers.get("X-Hub-Signature-256")
    if not sig_header or not sig_header.startswith("sha256="):
        logging.warning(f"Invalid or missing X-Hub-Signature-256 header: {sig_header}")
        return False

    sent_sig = sig_header.split("=", 1)[1].strip()
    mac = hmac.new(GITHUB_WEBHOOK_SECRET.encode("utf-8"), msg=raw_body, digestmod=hashlib.sha256)
    expected_sig = mac.hexdigest()

    if not hmac.compare_digest(expected_sig, sent_sig):
        logging.info(f"Signature mismatch. expected={expected_sig} got={sent_sig}")
        return False
    return True

# ---------------------------------------------------------------------------
# Event handlers
# ---------------------------------------------------------------------------

EventHandler = Callable[[str, str, dict, Dict[str, str]], None]

def handle_ping(event_name: str, delivery_id: str, payload: dict, headers: Dict[str, str]) -> None:
    logging.info(f"Received ping: {payload.get('zen')}")

def handle_push(event_name: str, delivery_id: str, payload: dict, headers: Dict[str, str]) -> None:
    repo = payload.get("repository", {}).get("full_name")
    logging.info(f"Push event in {repo} delivery={delivery_id}")

def handle_pull_request(event_name: str, delivery_id: str, payload: dict, headers: Dict[str, str]) -> None:
    action = payload.get("action")
    repo = payload.get("repository", {}).get("full_name")
    logging.info(f"PR {action} in {repo} delivery={delivery_id}")

EVENT_HANDLERS: Dict[str, EventHandler] = {
    "ping": handle_ping,
    "push": handle_push,
    "pull_request": handle_pull_request,
}

# ---------------------------------------------------------------------------
# Worker thread
# ---------------------------------------------------------------------------

_event_queue: "queue.Queue[tuple[str, str, dict, Dict[str, str]]]" = queue.Queue()
_shutdown_event = threading.Event()

def _worker_loop() -> None:
    logging.info("Worker started.")
    while not _shutdown_event.is_set():
        try:
            event_name, delivery_id, payload, headers = _event_queue.get(timeout=0.5)
        except queue.Empty:
            continue
        try:
            handler = EVENT_HANDLERS.get(event_name)
            if handler:
                handler(event_name, delivery_id, payload, headers)
            else:
                logging.info(f"No handler for event '{event_name}'")
        except Exception:
            logging.exception(f"Error handling {event_name} {delivery_id}")
        finally:
            _event_queue.task_done()
    logging.info("Worker exiting.")

threading.Thread(target=_worker_loop, name="WebhookWorker", daemon=True).start()

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/health", methods=["GET"])
def health() -> Any:
    return jsonify({"status": "ok"})

@app.route("/webhook", methods=["POST"])
def github_webhook() -> Any:
    raw_body = request.get_data(cache=False, as_text=False)
    headers = {k: v for k, v in request.headers.items()}
    event_name = headers.get("X-GitHub-Event", "?")
    delivery_id = headers.get("X-GitHub-Delivery", "?")

    if event_name == "ping" and ALLOW_EMPTY_SECRET_FOR_PING and not GITHUB_WEBHOOK_SECRET:
        logging.info("Ping allowed without secret.")
    else:
        if not GITHUB_WEBHOOK_SECRET:
            abort(500, description="Missing webhook secret.")
        if not verify_github_signature(raw_body, headers):
            abort(403, description="Invalid signature.")

    try:
        payload = request.get_json(force=True)
    except Exception as exc:
        logging.info(f"Invalid JSON payload: {exc}")
        abort(400, description="Invalid JSON.")

    _event_queue.put((event_name, delivery_id, payload, headers))
    return jsonify({"status": "accepted", "event": event_name, "delivery": delivery_id})

# ---------------------------------------------------------------------------
# Shutdown
# ---------------------------------------------------------------------------

def _graceful_shutdown(*_: Any) -> None:
    logging.info("Shutdown signal received.")
    _shutdown_event.set()
    

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    signal.signal(signal.SIGINT, _graceful_shutdown)
    signal.signal(signal.SIGTERM, _graceful_shutdown)
    logging.info(f"Starting server at {HOST}:{PORT}")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s : %(message)s")
    app.run(host=HOST, port=PORT, debug=True, use_reloader=True)

    # ---------------------------------------------------------------------------
    # Logging
    # ---------------------------------------------------------------------------

    if not GITHUB_WEBHOOK_SECRET:
        logging.warning("Webhook secret is empty! Non-ping events will be rejected unless allowed by config.")


if __name__ == "__main__":
    main()
