"""Separate local first-journal executable; normal workers remain resume-only."""
import argparse
import fcntl
import os
from pathlib import Path
import secrets
import stat

from policy import canonical, digest, require, strict_json
import ticket_process_v1 as legacy
import ticket_renewing_process_v2 as renewing
from ticket_backend_resources_v1 import build as resources_build
from ticket_native_v1 import TicketNative
from ticket_first_journal_v1 import public_scope, run

PROFILE = 'nockapp-ticket-first-journal-local-process-v1'


def execute(mode, deployment, deployment_pin, intent, intent_pin, generated, directory):
    """Trusted root installer chooses all public paths/configuration.

    Runs as the exact role UID through the existing credential broker. The
    durable intent is exclusive; a failed/unknown create is observed, not retried.
    """
    require(mode in ('check', 'initialize', 'observe'), 'first-journal-mode')
    value = (renewing.preflight(deployment, deployment_pin)
             if deployment.get('profile') == renewing.PROFILE else legacy.preflight(deployment, deployment_pin))
    require(value['kind'] == 'role', 'first-journal-role')
    cfg = public_scope(value['backend'], value['backend_sha256'], intent, intent_pin, generated)
    require(intent['resources_sha256'] == value['resources_sha256']
        and intent['sealed_boot_sha256'] == value['resources']['sealed_boot_sha256'], 'first-journal-deployment-binding')
    if mode == 'check':
        return {'profile': PROFILE, 'ok': True, 'mode': mode, 'private_packet_read': False,
                'credentials_acquired': False, 'initialization_performed': False}
    directory = Path(directory)
    fd = legacy.open_path(str(directory), directory=True)
    lock = None
    result = {'profile': PROFILE, 'ok': False, 'mode': mode, 'deployment_sha256': deployment_pin,
              'intent_sha256': intent_pin, 'outcome_unknown': False, 'automatic_write_retry': False}
    try:
        info = os.fstat(fd)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'first-journal-status-directory')
        flags = os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        lock = os.open('setup.lock', flags | (os.O_RDONLY if mode == 'observe' else os.O_RDWR | os.O_CREAT),
                       0o600, dir_fd=fd)
        info = os.fstat(lock)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == 0, 'first-journal-status-lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        receipt = {'profile': PROFILE, 'deployment_sha256': deployment_pin, 'intent_sha256': intent_pin,
                   'sealed_boot_sha256': intent['sealed_boot_sha256'],
                   'generated_public_sha256': intent['generated_public_sha256']}
        if mode == 'initialize':
            owned = os.open('intent.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            0o600, dir_fd=fd)
            with os.fdopen(owned, 'wb') as stream:
                stream.write(canonical(receipt))
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(fd)
        else:
            require(strict_json(legacy.read_file(str(directory / 'intent.json'), 4096)) == receipt,
                    'first-journal-observer-intent')

        def save():
            # Archive every result; never overwrite the uncertain result.
            name = 'status-' + secrets.token_hex(12) + '.json'
            output = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=fd)
            with os.fdopen(output, 'wb') as stream:
                stream.write(canonical(result))
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(fd)

        result['outcome_unknown'] = True
        save()
        try:
            sealed = legacy.read_file(value['sealed_boot'], 100000, expected=intent['sealed_boot_sha256'])
            resources = resources_build(cfg, value['backend_sha256'], value['broker'], value['broker_sha256'],
                                        value['resources'], value['resources_sha256'])
            native = TicketNative(value['ticket_native'], cfg['ticket_native_sha256'])
            # A new scratch child is disposable public journal storage. This
            # preserves normal worker journal.sqlite and every prior attempt.
            scratch = Path(value['scratch']) / ('first-journal-' + secrets.token_hex(12))
            scratch.mkdir(mode=0o700)
            result['result'] = run(cfg, value['backend_sha256'], intent, intent_pin, generated, resources,
                                   sealed, ticket_native=native, scratch=scratch, observe=mode == 'observe')
            result.update(ok=True, outcome_unknown=False)
        except Exception:
            result['error'] = 'first-journal-setup-unavailable'
        save()
        return result
    finally:
        if lock is not None:
            os.close(lock)
        os.close(fd)


def main(argv=None):
    try:
        legacy.harden_process()
        class Parser(argparse.ArgumentParser):
            def error(self, _):
                raise ValueError('first-journal-arguments')
        parser = Parser(description=__doc__)
        parser.add_argument('mode', choices=('check', 'initialize', 'observe'))
        for name in ('deployment', 'sha256', 'intent', 'intent-sha256', 'generated-public', 'state-directory'):
            parser.add_argument('--' + name, required=True)
        try:
            args = parser.parse_args(argv)
        except SystemExit as error:
            return 0 if error.code == 0 else 1
        raw = legacy.read_file(args.deployment, 1048576, expected=args.sha256)
        value = strict_json(raw, max_bytes=1048576)
        require(canonical(value) == raw, 'first-journal-canonical-deployment')
        raw = legacy.read_file(args.intent, 65536, expected=args.intent_sha256)
        intent = strict_json(raw, max_bytes=65536)
        require(canonical(intent) == raw, 'first-journal-canonical-intent')
        raw = legacy.read_file(args.generated_public, 16384, expected=intent['generated_public_sha256'])
        generated = strict_json(raw, max_bytes=16384)
        require(canonical(generated) == raw, 'first-journal-canonical-generation')
        result = execute(args.mode, value, args.sha256, intent, args.intent_sha256, generated, args.state_directory)
        print(canonical(result).decode(), flush=True)
        return 0 if result['ok'] else 1
    except BaseException:
        print('{"ok":false,"code":"first-journal-process-rejected","automatic_write_retry":false}', flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
