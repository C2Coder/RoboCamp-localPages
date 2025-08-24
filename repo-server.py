import os
import yaml
import subprocess
import requests
import http.server
import socketserver
import threading
import time
from datetime import datetime
from dotenv import load_dotenv
from functools import partial

CONFIG_PATH = "config.yaml"

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config():
    load_dotenv()
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)

# ---------------------------------------------------------------------------
# GitHub Operations
# ---------------------------------------------------------------------------

def get_local_commit(branch, abs_path):
    return subprocess.check_output(["git", "rev-parse", branch], cwd=abs_path).strip().decode()

def get_remote_commit(repo, branch, token):
    headers = {"Authorization": f"Bearer {token}"}
    url = f"https://api.github.com/repos/{repo}/commits/{branch}"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()["sha"]

# ---------------------------------------------------------------------------
# Webhook Server Operations
# ---------------------------------------------------------------------------

def check_update_with_webhook_server(url, repo, branch, last_pull_time):
    if not url:
        raise ValueError("Webhook server URL is not configured.")
    response = requests.get(f"{url}/api/repo/{repo}/push")
    if response.status_code != 200:
        raise Exception(f"Failed to check webhook server: {response.status_code} {response.text}")
    rjson = response.json()

    if not isinstance(rjson, dict):
        raise Exception("Invalid response from webhook server: Expected a JSON object.")

    if "data" not in rjson.keys():
        raise Exception("Invalid response from webhook server: 'data' key not found.")

    data = rjson["data"]
    if not isinstance(data, list):
        raise Exception("Invalid response from webhook server: 'data' key is not a list.")

    if not data:
        print(f"No updates found for {repo} on branch {branch}.")
        return False

    pushes = [push for push in data if push.get("branch") == branch]

    if not pushes:
        print(f"No updates found for {repo} on branch {branch}.")
        return False
    
    latest_push = pushes[0]

    if "timestamp" not in latest_push:
        raise Exception("Invalid push data: 'timestamp' key not found.")

    latest_push_time = datetime.fromisoformat(latest_push["timestamp"])
    last_pull_dt = datetime.fromtimestamp(last_pull_time)
    if latest_push_time <= last_pull_dt:
        return False

    return True

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def ensure_repo_exists(repo_cfg):
    repo_path = repo_cfg["path"]
    github_repo = repo_cfg["repo"]
    branch = repo_cfg["branch"]

    if not os.path.isdir(repo_path) or not os.path.isdir(os.path.join(repo_path, ".git")):
        print(f"[{repo_cfg['name']}] Local repo not found. Cloning branch '{branch}' from GitHub...")
        clone_url = f"https://github.com/{github_repo}.git"
        subprocess.check_call(["git", "clone", "-b", branch, clone_url, repo_path])
    else:
        print(f"[{repo_cfg['name']}] Local repo exists.")

def pull_latest(abs_path):
    subprocess.check_call(["git", "pull"], cwd=abs_path)

def run_http_server(port, directory):
    handler_class = partial(http.server.SimpleHTTPRequestHandler, directory=directory)

    with socketserver.TCPServer(("", port), handler_class) as httpd:
        print(f"[{directory}] Serving HTTP on port {port}")
        httpd.serve_forever()

def watch_repo(repo_cfg, global_cfg, token):
    name = repo_cfg["name"]
    path = repo_cfg["path"]
    abs_path = global_cfg["root_cwd"]+ "/" + path.strip("./")
    github_repo = repo_cfg["repo"]
    branch = repo_cfg["branch"]

    update_method = repo_cfg.get("update_method", "github").lower()
    host_http = repo_cfg.get("host_http_server", False)
    http_port = repo_cfg.get("http_port", 8080)

    github_interval = global_cfg.get("github_poll_interval", 60)
    webhook_interval = global_cfg.get("webhook_poll_interval", 30)
    webhook_base_url = global_cfg.get("webhook_base_url", "")

    ensure_repo_exists(repo_cfg)

    if host_http:
        threading.Thread(target=run_http_server, args=(http_port, abs_path), daemon=True).start()

    last_github_check = 0
    last_webhook_check = 0
    last_pull_time = 0

    while True:
        now = time.time()
        try:
            local_commit = get_local_commit(branch, abs_path)

            if update_method in ("github", "both") and now - last_github_check >= github_interval:
                remote_commit = get_remote_commit(github_repo, branch, token)
                if local_commit != remote_commit:
                    print(f"[{name}] GitHub update detected. Pulling...")
                    pull_latest(abs_path)
                    last_pull_time = now
                else:
                    print(f"[{name}] GitHub: Up to date.")
                last_github_check = now

            if update_method in ("webhook", "both") and now - last_webhook_check >= webhook_interval:
                if check_update_with_webhook_server(webhook_base_url, github_repo, branch, last_pull_time):
                    print(f"[{name}] Webhook server reports update. Pulling...")
                    pull_latest(abs_path)
                    last_pull_time = now
                else:
                    print(f"[{name}] Webhook: No update.")
                last_webhook_check = now

        except Exception as e:
            print(f"[{name}] Error: {e}")

        time.sleep(5)

# ---------------------------------------------------------------------------
# Main Function
# ---------------------------------------------------------------------------

def main():

    root_cwd = os.getcwd()
    print(f"Current working directory: {root_cwd}")
    config = load_config()
    token = os.getenv("GITHUB_TOKEN")

    if not os.path.exists("repo"):
        os.makedirs("repo", exist_ok=True)
        print("Created 'repo' directory.")

    if not token:
        print("Missing GITHUB_TOKEN in environment")
        return

    global_cfg = {
        "github_poll_interval": int(config.get("github_poll_interval", 60)),
        "webhook_poll_interval": int(config.get("webhook_poll_interval", 30)),
        "webhook_base_url": str(config.get("webhook_base_url", "")),
        "root_cwd": str(root_cwd)
    }

    for repo_cfg in config["repositories"]:
        threading.Thread(
            target=watch_repo,
            args=(repo_cfg, global_cfg, token),
            daemon=True
        ).start()

    while True:
        time.sleep(600)

if __name__ == "__main__":
    main()

# TODO: Working directories