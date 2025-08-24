# RoboCamp-localPages



## Install

```bash
sudo apt update
sudo apt upgrade -y
sudo apt install python3-venv git -y
```

Create venv
```bash
python3 -m venv .venv
```

Activate venv
```bash
source .venv/bin/activate
```

Create `.env` file with:
```conf
GITHUB_WEBHOOK_SECRET=your-webhook-secret
GITHUB_TOKEN=your-github-token
```

## RUN DNS
```bash
sudo ./.venv/bin/python3 dns-server.py
```

## RUN REPO SERVER
```bash
python3 repo-server.py
```

## RUN WEBHOOK SERVER (not needed)
```bash
sudo cp ./webhook-nginx.conf /etc/nginx/sites-available/github-webhook
sudo ln -s /etc/nginx/sites-available/github-webhook /etc/nginx/sites-enabled/
```

python3 webhook-server.py