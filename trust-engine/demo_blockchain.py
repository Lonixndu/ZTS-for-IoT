"""Compatibility entry point; register/import on Member 3 before this demo."""
import sys
from demo_behavior_events import main

if __name__ == '__main__':
    if '--register' not in sys.argv:
        sys.argv.extend(['--register', 'blockchain'])
    main()
