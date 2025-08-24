
Create venv
```bash
python -m venv .venv
```

Activate venv
```bash
source .venv/bin/activate
```

Install certbot wedos extension
```bash
pip install certbot-dns-wedos
```

Get the certificates
```bash
.venv/bin/certbot certonly \
    --authenticator dns-wedos \
    --dns-wedos-propagation-seconds 450 \
    --dns-wedos-credentials /home/c2coder/config/wedos/wapi-my.ini \
    -d c2coder.eu
```