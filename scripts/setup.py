"""Create local secrets without overwriting an existing configuration."""

import os
import secrets
from pathlib import Path

root = Path(__file__).resolve().parents[1]
destination = root / ".env"
if destination.exists():
    raise SystemExit(".env already exists; kept existing settings.")
password = secrets.token_hex(24)
content = (
    (root / ".env.example")
    .read_text()
    .replace("SECRET_KEY=\n", "SECRET_KEY=" + secrets.token_urlsafe(48) + "\n")
    .replace("POSTGRES_PASSWORD=\n", "POSTGRES_PASSWORD=" + password + "\n")
    .replace("REPLACE_PASSWORD", password)
)
with destination.open("x") as stream:
    stream.write(content)
os.chmod(destination, 0o600)
print("Created .env. Next: docker compose up --build -d")
