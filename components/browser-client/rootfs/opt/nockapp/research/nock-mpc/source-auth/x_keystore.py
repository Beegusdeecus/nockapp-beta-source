"""Ubuntu Secret Service holder keys; no plaintext files, argv or fallback.

Only NockApp's exact application/key-ID attributes are queried. Read-only
default-collection metadata is checked before key operations; locked/unconfigured
storage fails explicitly. Secret bytes travel only through bounded private pipes.
"""
import base64
import contextlib
import ctypes
import fcntl
import os
from pathlib import Path
import re
import resource
import secrets
import selectors
import stat
import subprocess
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from x_policy import canonical, loads, holder_id
from x_holder import public_hex, sign_issuance, sign_action

PROFILE = 'nockapp-ubuntu-secret-service-holder-v1'
APPLICATION = 'org.nockapp.XPassports'
PREFIX = b'NOCKAPP-HOLDER-P256-v1:'
ERRORS = {'keyring-unavailable', 'keyring-unconfigured', 'keyring-locked', 'holder-key-missing',
          'holder-key-invalid', 'holder-state-invalid', 'holder-busy', 'holder-storage-failed', 'private-process-unavailable'}


class KeyStoreRejected(Exception):
    def __init__(self, code):
        super().__init__(code if code in ERRORS else 'holder-storage-failed')


def fail(code):
    raise KeyStoreRejected(code) from None


class SecretService:
    def __init__(self):
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            if ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0) != 0:
                fail('private-process-unavailable')
        except KeyStoreRejected:
            raise
        except Exception:
            fail('private-process-unavailable')
        address = os.environ.get('DBUS_SESSION_BUS_ADDRESS', '')
        if re.fullmatch(r'unix:(?:path|abstract)=[A-Za-z0-9_./-]+(?:,guid=[0-9a-f]{32})?', address) is None:
            fail('keyring-unavailable')
        self.environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'DBUS_SESSION_BUS_ADDRESS': address}
        # No DISPLAY/XAUTHORITY or imported shell environment: this broker does
        # not prompt. The user unlocks/configures the desktop collection itself.

    def _run(self, arguments, data=None, *, limit=4096, timeout=3):
        process = None
        try:
            process = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, env=self.environment)
            if data is not None:
                if type(data) is not bytes or len(data) > 1024:
                    fail('holder-storage-failed')
                process.stdin.write(data)
            process.stdin.close()
            output = {'out': bytearray(), 'err': bytearray()}
            deadline = time.monotonic() + timeout
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, 'out')
                selector.register(process.stderr, selectors.EVENT_READ, 'err')
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        fail('keyring-unavailable')
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fileobj.fileno(), 1024)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        output[key.data].extend(chunk)
                        if len(output[key.data]) > (limit if key.data == 'out' else 4096):
                            fail('holder-storage-failed')
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
            return process.returncode, bytes(output['out']), bool(output['err'])
        except KeyStoreRejected:
            raise
        except Exception:
            fail('keyring-unavailable')
        finally:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.wait()
                for stream in (process.stdin, process.stdout, process.stderr):
                    stream.close()

    def _dbus(self, destination, path, method, *arguments):
        status, output, error = self._run(['/usr/bin/gdbus', 'call', '--session', '--dest', destination,
            '--object-path', path, '--method', method, *arguments])
        if status or error:
            fail('keyring-unavailable')
        return output

    def ready(self):
        owner = self._dbus('org.freedesktop.DBus', '/org/freedesktop/DBus',
                           'org.freedesktop.DBus.NameHasOwner', 'org.freedesktop.secrets')
        if owner != b'(true,)\n':
            fail('keyring-unavailable')
        alias = self._dbus('org.freedesktop.secrets', '/org/freedesktop/secrets',
                           'org.freedesktop.Secret.Service.ReadAlias', 'default')
        matched = re.fullmatch(rb"\((?:objectpath )?'(/[A-Za-z0-9_/]*)',\)\n", alias)
        if matched is None:
            fail('keyring-unconfigured')
        collection = matched[1].decode('ascii')
        if (not collection.startswith('/org/freedesktop/secrets/collection/') or collection.endswith('/session')
                or collection.endswith('/') or '//' in collection):
            fail('keyring-unconfigured')
        locked = self._dbus('org.freedesktop.secrets', collection, 'org.freedesktop.DBus.Properties.Get',
                            'org.freedesktop.Secret.Collection', 'Locked')
        if locked == b'(<true>,)\n':
            fail('keyring-locked')
        if locked != b'(<false>,)\n':
            fail('keyring-unavailable')
        return collection

    @staticmethod
    def attributes(key_id):
        if type(key_id) is not str or re.fullmatch('[0-9a-f]{32}', key_id) is None:
            fail('holder-state-invalid')
        return ['application', APPLICATION, 'holder-key-id', key_id, 'format', '1']

    def store(self, key_id, value):
        self.ready()
        status, output, error = self._run(['/usr/bin/secret-tool', 'store', '--label=NockApp X passport holder key',
                                          *self.attributes(key_id)], value, limit=1024)
        if status or error or output:
            fail('holder-storage-failed')

    def lookup(self, key_id):
        self.ready()
        status, output, error = self._run(['/usr/bin/secret-tool', 'lookup', *self.attributes(key_id)], limit=1024)
        if status == 1 and not output and not error:
            fail('holder-key-missing')
        if status or error or not output:
            fail('keyring-unavailable')
        return output

    def clear(self, key_id):
        self.ready()
        try:
            self.lookup(key_id)
        except KeyStoreRejected as error:
            if error.args[0] == 'holder-key-missing':
                return
            raise
        status, output, error = self._run(['/usr/bin/secret-tool', 'clear', *self.attributes(key_id)], limit=1024)
        if status or output or error:
            fail('holder-storage-failed')


class HolderStore:
    def __init__(self, directory):
        self.directory = Path(directory)
        if not self.directory.is_absolute() or self.directory.is_symlink():
            fail('holder-state-invalid')
        self.directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        info = self.directory.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            fail('holder-state-invalid')
        self.metadata = self.directory / 'holder-public.json'

    @contextlib.contextmanager
    def _lock(self):
        fd = os.open(self.directory / 'holder.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
                fail('holder-state-invalid')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                fail('holder-busy')
            yield
        finally:
            os.close(fd)

    def _public(self):
        try:
            fd = os.open(self.metadata, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return None
        except OSError:
            fail('holder-state-invalid')
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077
                    or info.st_nlink != 1 or not 0 < info.st_size <= 8192):
                fail('holder-state-invalid')
            with os.fdopen(fd, 'rb') as stream:
                fd = None
                value = loads(stream.read(8193))
            if type(value) is not dict or set(value) != {'profile', 'key_id', 'holder_public_key', 'holder_key', 'created_at'}:
                fail('holder-state-invalid')
            SecretService.attributes(value['key_id'])
            if (value['profile'] != PROFILE or type(value['created_at']) is not int or value['created_at'] <= 0
                    or holder_id(value['holder_public_key']) != value['holder_key']):
                fail('holder-state-invalid')
            return value
        except KeyStoreRejected:
            raise
        except Exception:
            fail('holder-state-invalid')
        finally:
            if fd is not None:
                os.close(fd)

    def public(self):
        with self._lock():
            value = self._public()
            if value is None:
                fail('holder-key-missing')
            return value

    @staticmethod
    def _key(service, metadata):
        secret = service.lookup(metadata['key_id'])
        try:
            if not secret.startswith(PREFIX):
                fail('holder-key-invalid')
            encoded = secret[len(PREFIX):]
            raw = base64.b64decode(encoded, validate=True)
            if base64.b64encode(raw) != encoded:
                fail('holder-key-invalid')
            key = serialization.load_der_private_key(raw, password=None)
            if public_hex(key) != metadata['holder_public_key']:
                fail('holder-key-invalid')
            return key
        except KeyStoreRejected:
            raise
        except Exception:
            fail('holder-key-invalid')
        finally:
            del secret

    def ensure(self):
        with self._lock():
            service = SecretService()
            service.ready()
            existing = self._public()
            if existing is not None:
                key = self._key(service, existing)
                del key
                return existing
            key = ec.generate_private_key(ec.SECP256R1())
            public = public_hex(key)
            value = {'profile': PROFILE, 'key_id': secrets.token_hex(16), 'holder_public_key': public,
                     'holder_key': holder_id(public), 'created_at': int(time.time())}
            raw = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
            secret = PREFIX + base64.b64encode(raw)
            del raw, key
            stored = False
            temporary = self.directory / ('.holder-' + secrets.token_hex(16) + '.json')
            try:
                service.store(value['key_id'], secret)
                stored = True
                del secret
                key = self._key(service, value)
                del key
                fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, 'wb') as output:
                    output.write(canonical(value))
                    output.flush()
                    os.fsync(output.fileno())
                os.link(temporary, self.metadata)
                temporary.unlink()
                return value
            except Exception as error:
                if stored:
                    try:
                        service.clear(value['key_id'])
                    except Exception:
                        pass
                if isinstance(error, KeyStoreRejected):
                    raise
                fail('holder-storage-failed')
            finally:
                if temporary.exists():
                    temporary.unlink()

    def sign_issuance(self, ticket):
        with self._lock():
            metadata = self._public()
            if metadata is None:
                fail('holder-key-missing')
            if type(ticket) is not dict or ticket.get('holder_public_key') != metadata['holder_public_key']:
                fail('holder-key-invalid')
            key = self._key(SecretService(), metadata)
            return sign_issuance(key, ticket)

    def sign_action(self, action):
        with self._lock():
            metadata = self._public()
            if metadata is None:
                fail('holder-key-missing')
            key = self._key(SecretService(), metadata)
            return sign_action(key, action)

    def delete(self):
        with self._lock():
            metadata = self._public()
            if metadata is None:
                return
            SecretService().clear(metadata['key_id'])
            self.metadata.unlink()
