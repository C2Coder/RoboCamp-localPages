# RoboCamp-localPages



## Install

```bash
sudo apt update
sudo apt upgrade -y
sudo apt install python3-venv git -y
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
sudo cp ./webhook-nginx.conf /etc/nginx/sites-available/github-webhook
sudo ln -s /etc/nginx/sites-available/github-webhook /etc/nginx/sites-enabled/
```

Create `.env` file with:
```conf
GITHUB_WEBHOOK_SECRET=<your-webhook-secret>
GITHUB_TOKEN=<your-github-token> 
```

## RUN DNS
```bash
sudo ./.venv/bin/python3 dns-server.py --config dns-config.yaml
```

