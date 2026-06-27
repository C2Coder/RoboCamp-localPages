# RoboCamp-localPages

## Install

```bash
sudo apt update
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

Rename `.env.example` to `.env` and edit to your liking:

## Run Repo Server

Edit the `config.yaml` file to match what you need

Setup nginx for correct 
```bash
python3 nginx-builder.py
sudo cp ./nginx.conf /etc/nginx/sites-available/localpages
sudo ln -s /etc/nginx/sites-available/localpages /etc/nginx/sites-enabled/
```

```bash
python3 repo-server.py
```

## Run Webhook Server (on a public ip and point github to it)
```bash
sudo cp ./webhook/nginx.conf /etc/nginx/sites-available/github-webhook
sudo ln -s /etc/nginx/sites-available/github-webhook /etc/nginx/sites-enabled/
```

```bash
python3 webhook-server.py
```