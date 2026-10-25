"""Read this project's simple KEY=VALUE .env file without executing its contents."""
import os
from pathlib import Path
import re


def load_local_env(path='.env'):
    file = Path(path)
    if not file.exists():
        return
    for number, line in enumerate(file.read_text(encoding='utf-8-sig').splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        key, value = key.strip(), value.strip()
        if not separator or not re.fullmatch(r'(?:TRUST|BLOCKCHAIN)_[A-Z0-9_]+', key):
            raise ValueError(f'invalid project setting on line {number} of {file.name}')
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        # Values are literal: no shell interpolation and no backslash expansion.
        os.environ.setdefault(key, value)
