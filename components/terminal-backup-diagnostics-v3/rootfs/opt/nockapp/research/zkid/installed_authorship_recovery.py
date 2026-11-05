"""Terminal-only recovery inside the frozen desktop sandbox.

The launcher chooses the installed configuration and fixed backup mount. No
browser operation, caller-selected wallet, plaintext output or key rotation.
"""
import getpass
from pathlib import Path
import sys
import time

from policy import require, Rejected
from wallet import KeyStoreRejected
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
    except Exception as error:
        # Fixed messages only: exception text may contain sensitive provider data.
        messages={
            'backup-passphrase-length':'Use a longer passphrase: at least 16 UTF-8 bytes (16 ordinary characters suffice). Nothing was exported.',
            'backup-passphrase-mismatch':'The passphrase entries did not match. Nothing was exported.',
            'keyring-locked':'Your desktop keyring is locked. Unlock the existing login keyring, then retry. Do not create a replacement identity.',
            'keyring-unavailable':'The existing desktop keyring could not be reached. Keep your desktop session open; do not create a replacement identity.',
            'keyring-unconfigured':'The existing desktop keyring is unavailable. Do not create a replacement identity.',
            'holder-key-missing':'The existing keyring entry could not be found. Keep existing app data; do not create a replacement identity.',
            'desktop-busy':'NockApp is busy. Wait for its current operation to finish, then retry.',
            'wallet-busy':'NockApp is busy. Wait for its current operation to finish, then retry.',
        }
        code=error.args[0] if isinstance(error,(Rejected,KeyStoreRejected)) and len(error.args)==1 and type(error.args[0]) is str else None
        print(messages.get(code,'Recovery could not complete. Existing identities were not replaced.'),file=sys.stderr)
        return 1
