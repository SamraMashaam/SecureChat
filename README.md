pip install -r requirements.txt

python -m venv .venv
.\.venv\Scripts\Activate.ps1

python scripts/gen_ca.py

python scripts/gen_cert.py --type server --cn "securechat.server"
python scripts/gen_cert.py --type client --cn "securechat.client"

python -m app.server
python -m app.client
