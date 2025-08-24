import yaml
from dotenv import load_dotenv

CONFIG_PATH = "config.yaml"

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config():
    load_dotenv()
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)

def main():
    config = load_config()
    cfg = []

    for repo in config.get("repositories", []):
        if not isinstance(repo, dict):
            print("Invalid repository configuration, skipping.")
            continue
            
        if "domain" not in repo or "http_port" not in repo:
            print(f"Repository {repo.get('name', 'unknown')} is missing required fields, skipping.")
            continue
    
        cfg.append(f"# {repo['name']} - {repo.get('domain', '')}")
        
        cfg.append(f"server {{  # HTTP")
        cfg.append(f"    listen 80;")
        cfg.append(f"    server_name {repo['domain']};")
        cfg.append(f"    location / {{")
        cfg.append(f"        proxy_pass http://localhost:{repo['http_port']};")
        cfg.append(f"        proxy_set_header Host $host;")
        cfg.append(f"        proxy_set_header X-Real-IP $remote_addr;")
        cfg.append(f"        proxy_set_header X-Forwarded-For $proxy_addr;")
        cfg.append(f"        proxy_set_header X-Forwarded-Proto $scheme;")
        cfg.append(f"    }}")
        cfg.append(f"}}")
        cfg.append(f"server {{  # HTTPS")
        cfg.append(f"    listen 443 ssl;")
        cfg.append(f"    server_name {repo['domain']};")
        cfg.append(f"    ssl_certificate /etc/letsencrypt/live/{repo['name']}/fullchain.pem;")
        cfg.append(f"    ssl_certificate_key /etc/letsencrypt/live/{repo['name']}/privkey.pem;")
        cfg.append(f"    ssl_protocols TLSv1.2 TLSv1.3;")
        cfg.append(f"    ssl_prefer_server_ciphers on;")
        cfg.append(f"    location / {{")
        cfg.append(f"        proxy_pass http://localhost:{repo['http_port']};")
        cfg.append(f"        proxy_set_header Host $host;")
        cfg.append(f"        proxy_set_header X-Real-IP $remote_addr;")
        cfg.append(f"        proxy_set_header X-Forwarded-For $proxy_addr;")
        cfg.append(f"        proxy_set_header X-Forwarded-Proto $scheme;")
        cfg.append(f"    }}")
        cfg.append(f"}}")
        cfg.append("")  # Add a blank line for readability

    with open("nginx.conf", "w") as f:
        for entry in cfg:
            f.write(entry + "\n")


if __name__ == "__main__":
    main()