"""Terminal-only recovery inside the frozen desktop sandbox.

The launcher chooses the installed configuration and fixed backup mount. No
browser operation, caller-selected wallet, plaintext output or key rotation.
"""
import getpass
from pathlib import Path
import sys
import time

from policy import require
from portable_authorship import backup, restore, read_file

BACKUP_FILE = '/tmp/portable-authorship-backup'


def run(action, *, configuration=None, factory=None, root=None):
    require(action in ('backup', 'restore') and sys.stdin.isatty()
        and sys.stderr.isatty(), 'backup-local-terminal-required')
    if configuration is None:
        from domain_native import configuration
    if factory is None:
        from public_installation import factory
    root = Path(__file__).resolve().parent if root is None else root
    config = configuration()
    require(config.get('profile') in ('nockapp-installed-public-native-v6',
        'nockapp-installed-public-native-v7', 'nockapp-installed-public-direct-v1',
        'nockapp-installed-public-renewal-v1'), 'backup-public-installation-required')
    # The pinned factory retains existing identity/legacy bindings and validates
    # all code/binary inputs. Construction makes no source or chain request.
    author = factory(config, root).desktop.author
    print('This recovers your authorship secret. Credentials and prepaid tickets are separate.', file=sys.stderr)
    phrase = getpass.getpass('Backup passphrase (use a strong unique phrase): ')
    if action == 'backup':
        require(phrase == getpass.getpass('Repeat passphrase: '), 'backup-passphrase-mismatch')
        data = backup(author, phrase, True)
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    else:
        restore(author, read_file(BACKUP_FILE), phrase, int(time.time()), True)
    return 0


def main(action):
    try:
        return run(action)
    except Exception:
        print('Recovery could not complete. Existing identities were not replaced.', file=sys.stderr)
        return 1
