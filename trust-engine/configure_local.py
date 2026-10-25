"""Create local demo credentials once. Does not print or overwrite secrets."""
from pathlib import Path
import secrets


def main():
    root = Path(__file__).resolve().parent
    template = (root / '.env.example').read_text(encoding='utf-8')
    template = template.replace('GENERATE_SERVICE_TOKEN', secrets.token_urlsafe(32))
    template = template.replace('GENERATE_ADMIN_TOKEN', secrets.token_urlsafe(32))
    try:
        with (root / '.env').open('x', encoding='utf-8') as stream:
            stream.write(template)
    except FileExistsError:
        raise SystemExit('.env already exists; kept its settings and credentials unchanged.')
    print('Created .env with separate AI and admin credentials. Keep this file private.')


if __name__ == '__main__':
    main()
