from __future__ import annotations
from datetime import datetime
from dotenv import load_dotenv
from typing import Any, Callable, Dict
from flask import Flask, request, abort, jsonify

import os
import sys
import hmac
import time
import json
import yaml
import queue
import signal
import hashlib
import threading

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
        log(f"Failed to load config {path}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

load_dotenv()  # take environment variables
CFG = load_config(CONFIG_FILE)
GITHUB_WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", CFG["webhook"].get("secret", ""))
MAX_CONTENT_LENGTH = int(CFG["server"].get("max_content_length", 5 * 1024 * 1024))
HOST = str(CFG["server"].get("host", "0.0.0.0"))
PORT = int(CFG["server"].get("port", 7070))

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def log(message: str) -> None:
    print(message)

    with open("webhook/webhook.log", "a", encoding="utf-8") as log_file:
        log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
    
    if message.startswith("[") and "]" in message:
        # If the message contains an event type, log it to a separate file
        event_type = message.split("]")[0][1:]
        with open(f"webhook/webhook-{event_type}.log", "a", encoding="utf-8") as event_log_file:
            event_log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")


# ---------------------------------------------------------------------------
# Data store
# ---------------------------------------------------------------------------

data_store = {
    "ping": [],
    "push": [],
    "pull_request": [],
    "page_build": [],
    "deployment": [],
    "deployment_status": [],
    "workflow_run": [],
    "check_run": [],
    "workflow_job": [],
}

def get_data(event_name: str) -> list:
    """Get data for a specific event type."""
    if event_name not in data_store:
        log(f"Unknown event type: {event_name}")
        return []
    return data_store[event_name]

def add_data(event_name: str, data: dict) -> None:
    """Add data for a specific event type."""
    if event_name not in data_store:
        log(f"Unknown event type: {event_name}")
        return
    data_store[event_name].append(data)
    if "timestamp" in data:
        data_store["last_update"][event_name] = data["timestamp"]
    else:
        data_store["last_update"][event_name] = datetime.now().isoformat()
    log(f"Data added for {event_name}: {data}")

    save_data()  # Save data after each addition

def save_data(filename: str = "webhook/data_store.json") -> None:
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data_store, f, ensure_ascii=False, indent=2)
    except Exception as exc:
        log(f"Failed to save data store: {exc}")

def load_data(filename: str = "webhook/data_store.json") -> None:
    global data_store
    try:
        if os.path.exists(filename):
            with open(filename, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            # Only update known event types
            for k in data_store:
                if k in loaded:
                    data_store[k] = loaded[k]
            log(f"Data store loaded from {filename}")
    except Exception as exc:
        log(f"Failed to load data store: {exc}")

# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

def prepare_data(event_name: str, repo: str) -> dict:
    """Prepare the data for the api."""
    if event_name not in data_store:
        log(f"Unknown event type: {event_name}")
        return {"error": "Unknown event type"}
    
    events = data_store[event_name]
    if not events:
        log(f"No data for event type: {event_name}")
        return {"error": "No data available"}
    
    data = []
    for event in events:
        if event.get("repository") == repo:
            data.append(event)

    response = {
        "event": event_name,
        "repository": repo,
        "data": data,
    }

    return response

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
        log(f"Invalid or missing X-Hub-Signature-256 header: {sig_header}")
        return False

    sent_sig = sig_header.split("=", 1)[1].strip()
    expected_sig = hmac.new(GITHUB_WEBHOOK_SECRET.encode("utf-8"), msg=raw_body, digestmod=hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_sig, sent_sig):
        log(f"Signature mismatch. expected={expected_sig} got={sent_sig}")
        return False
    return True

# ---------------------------------------------------------------------------
# Event handlers
# ---------------------------------------------------------------------------

EventHandler = Callable[[str, str, dict, Dict[str, str]], None]

def handle_ping(event_name: str, delivery_id: str, payload: dict, headers: Dict[str, str]) -> None:
    log(f"[ping] Received ping: {payload.get('zen')}")

def handle_push(event_name: str, delivery_id: str, payload: dict, headers: Dict[str, str]) -> None:
    branch = payload.get("ref", "").split("/")[-1]
    repo = payload.get("repository", {}).get("full_name")
    log(f"[push] Push event in {repo} branch={branch} delivery={delivery_id}")

    data = {
        "repository": repo,
        "branch": branch,
        "pusher": payload.get("pusher", {}).get("name"),
        "timestamp": datetime.now().isoformat(),
    }
    add_data(event_name, data)

def handle_pull_request(event_name: str, delivery_id: str, payload: dict, headers: Dict[str, str]) -> None:
    action = payload.get("action")
    repo = payload.get("repository", {}).get("full_name")
    log(f"[pull_request] PR {action} in {repo} delivery={delivery_id}")

    data = {
        "repository": repo,
        "action": action,
        "pull_request": payload.get("pull_request", {}),
        "sender": payload.get("sender", {}).get("login"),
        "timestamp": datetime.now().isoformat(),
    }
    add_data(event_name, data)

def handle_page_build(event_name: str, delivery_id: str, payload: dict, headers: Dict[str, str]) -> None:
    build_status = payload.get("build", {}).get("status")
    repo = payload.get("repository", {}).get("full_name")
    log(f"[page_build] Pages build {build_status} in {repo} delivery={delivery_id}")

    data = {
        "repository": repo,
        "build_status": build_status,
        "sender": payload.get("sender", {}).get("login"),
        "timestamp": datetime.now().isoformat(),
    }
    add_data(event_name, data)

def handle_deployment(event_name: str, delivery_id: str, payload: dict, headers: Dict[str, str]) -> None:
    task = payload.get("deployment", {}).get("task")
    repo = payload.get("repository", {}).get("full_name")
    log(f"[deployment] Deployment {task} in {repo} delivery={delivery_id}")

    data = {
        "repository": repo,
        "task": task,
        "sender": payload.get("sender", {}).get("login"),
        "timestamp": datetime.now().isoformat(),
    }
    add_data(event_name, data)

def handle_deployment_status(event_name: str, delivery_id: str, payload: dict, headers: Dict[str, str]) -> None:
    deployment_status = payload.get("deployment_status", {}).get("state")
    repo = payload.get("repository", {}).get("full_name")
    log(f"[deployment_status] Deployment {deployment_status} in {repo} delivery={delivery_id}")

    data = {
        "repository": repo,
        "deployment_status": deployment_status,
        "sender": payload.get("sender", {}).get("login"),
        "timestamp": datetime.now().isoformat(),
    }
    add_data(event_name, data)

def handle_workflow_run(event_name: str, delivery_id: str, payload: dict, headers: Dict[str, str]) -> None:
    run_status = payload.get("workflow_run", {}).get("status")
    repo = payload.get("repository", {}).get("full_name")
    name = payload.get("workflow_run", {}).get("name")
    log(f"[workflow_run] Workflow run {run_status} in {repo} delivery={delivery_id} name={name}")

    data = {
        "repository": repo,
        "name": name,
        "run_status": run_status,
        "sender": payload.get("sender", {}).get("login"),
        "timestamp": datetime.now().isoformat(),
    }
    add_data(event_name, data)

def handle_check_run(event_name: str, delivery_id: str, payload: dict, headers: Dict[str, str]) -> None:
    check_run_status = payload.get("check_run", {}).get("status")
    repo = payload.get("repository", {}).get("full_name")
    name = payload.get("check_run", {}).get("name")
    log(f"[check_run] Check run {check_run_status} in {repo} delivery={delivery_id} name={name}")

    data = {
        "repository": repo,
        "name": name,
        "check_run_status": check_run_status,
        "sender": payload.get("sender", {}).get("login"),
        "timestamp": datetime.now().isoformat(),
    }
    add_data(event_name, data)

def handle_workflow_job(event_name: str, delivery_id: str, payload: dict, headers: Dict[str, str]) -> None:
    job_status = payload.get("workflow_job", {}).get("status")
    repo = payload.get("repository", {}).get("full_name")
    name = payload.get("workflow_job", {}).get("name")
    log(f"[workflow_job] Workflow job {job_status} in {repo} delivery={delivery_id} name={name}")

    data = {
        "repository": repo,
        "name": name,
        "job_status": job_status,
        "sender": payload.get("sender", {}).get("login"),
        "timestamp": datetime.now().isoformat(),
    }
    add_data(event_name, data)

def handle_check_suite(event_name: str, delivery_id: str, payload: dict, headers: Dict[str, str]) -> None:
    check_suite_status = payload.get("check_suite", {}).get("status")
    repo = payload.get("repository", {}).get("full_name")
    log(f"[check_suite] Check suite {check_suite_status} in {repo} delivery={delivery_id}")

    data = {
        "repository": repo,
        "check_suite_status": check_suite_status,
        "sender": payload.get("sender", {}).get("login"),
        "timestamp": datetime.now().isoformat(),
    }
    add_data(event_name, data)

EVENT_HANDLERS: Dict[str, EventHandler] = {
    "ping": handle_ping,
    "push": handle_push,
    "pull_request": handle_pull_request,
    "page_build": handle_page_build,
    "deployment": handle_deployment,
    "deployment_status": handle_deployment_status,
    "workflow_run": handle_workflow_run,
    "check_run": handle_check_run,
    "workflow_job": handle_workflow_job,
    "check_suite": handle_check_suite,
}

# ---------------------------------------------------------------------------
# Worker thread
# ---------------------------------------------------------------------------

_event_queue: "queue.Queue[tuple[str, str, dict, Dict[str, str]]]" = queue.Queue()
_shutdown_event = threading.Event()

def _worker_loop() -> None:
    log("Worker started.")
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
                log(f"No handler for event '{event_name}'")
                log(f"Payload: {payload}")
        except Exception:
            log(f"Error handling {event_name} {delivery_id}")
        finally:
            _event_queue.task_done()
    log("Worker exiting.")
    

threading.Thread(target=_worker_loop, name="WebhookWorker", daemon=True).start()

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index() -> Any:
    return jsonify({"message": "Webhook server is running."})

@app.route("/health", methods=["GET"])
def health() -> Any:
    return jsonify({"status": "ok"})

@app.route("/webhook", methods=["POST"])
def github_webhook() -> Any:
    raw_body = request.get_data(cache=False, as_text=False)
    headers = {k: v for k, v in request.headers.items()}
    event_name = headers.get("X-Github-Event", "?")
    delivery_id = headers.get("X-Github-Delivery", "?")

    if not GITHUB_WEBHOOK_SECRET:
        log("Webhook secret is not set.")
        abort(500, description="Missing webhook secret.")
    if not verify_github_signature(raw_body, headers):
        log(f"Invalid signature for event {event_name} delivery {delivery_id}")
        abort(403, description="Invalid signature.")
    
    try:
        payload = json.loads(raw_body.decode("utf-8", errors="replace"))
    except Exception as exc:
        log(f"Invalid JSON payload: {exc}")
        abort(400, description="Invalid JSON.")

    _event_queue.put((event_name, delivery_id, payload, headers))
    return jsonify({"status": "accepted", "event": event_name, "delivery": delivery_id})

@app.route("/api/repo/<string:repo_author>/<string:repo_name>/<string:event>", methods=["GET"])
def get_repo_data(repo_author: str, repo_name: str, event: str) -> Any:
    """Get data for a specific repository."""
    repo = f"{repo_author.strip()}/{repo_name.strip()}"

    if not repo or repo == "/":
        log("Repository name is empty.")
        abort(400, description="Repository name is required.")

    data = prepare_data(event, repo)
    if not data:
        log(f"No data found for repository {repo}")
        return jsonify({"error": "No data available for this repository"}), 404
    
    return jsonify(data)

# ---------------------------------------------------------------------------
# Shutdown
# ---------------------------------------------------------------------------

def _graceful_shutdown(*_: Any) -> None:
    log("Shutdown signal received.")
    save_data()
    _shutdown_event.set()
    time.sleep(1)  # Allow worker to finish processing
    sys.exit(0)
    

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    signal.signal(signal.SIGINT, _graceful_shutdown)
    signal.signal(signal.SIGTERM, _graceful_shutdown)

    if not os.path.exists("webhook"):
        os.makedirs("webhook", exist_ok=True)
        log("Created webhook directory.")

    log("Loading data store at startup...")
    try:
        load_data()
    except Exception as e:
        log(f"Error loading data store: {e}")

    log(f"Starting server at {HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=False, use_reloader=True)
    log("Server stopped.")

    if not GITHUB_WEBHOOK_SECRET:
        log("Webhook secret is empty! Non-ping events will be rejected unless allowed by config.")


if __name__ == "__main__":
    main()
