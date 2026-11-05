"""Protected Ubuntu storage for the NEW blind credential, separate from old keys.

Only the selected NockApp secret is queried. No plaintext persistent fallback,
interactive password collection, keyring enumeration, or automatic key rotation.
"""
import contextlib
import fcntl
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import stat
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Reuse the already tested narrow Secret Service transport, without modifying
# the old holder format or looking up any existing X-passport item.
SOURCE_AUTH = Path(__file__).resolve().parents[1]/'nock-mpc/source-auth'
sys.path.insert(0,str(SOURCE_AUTH))
from x_keystore import SecretService, KeyStoreRejected
from policy import Rejected, canonical, hex_string, require, strict_json

PROFILE='nockapp-zkid-protected-wallet-v1'
PREFIX=b'NOCKAPP-ZKID-SECRET-v1:'
MAX_PLAIN=131072
MAX_RECORD=MAX_PLAIN+28


class WalletSecretService(SecretService):
    @staticmethod
    def attributes(key_id):
        hex_string(key_id,32)
        return ['application','org.nockapp.ZKID.BlindCredentials','holder-key-id',key_id,'format','1']

    def store(self,key_id,value):
        self.ready()
        status,output,error=self._run(['/usr/bin/secret-tool','store','--label=NockApp private ZKID secret',
                                     *self.attributes(key_id)],value,limit=1024)
        require(not status and not output and not error,'wallet-storage-failed')


class Wallet:
    def __init__(self,directory):
        self.directory=Path(directory)
        require(self.directory.is_absolute() and not self.directory.is_symlink(),'wallet-directory')
        self.directory.mkdir(parents=True,mode=0o700,exist_ok=True)
        info=self.directory.stat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode & 0o077,
                'wallet-directory')

    @contextlib.contextmanager
    def controller_lock(self):
        """Serialize whole desktop transitions separately from record I/O."""
        fd=os.open(self.directory/'controller.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o077
                    and info.st_nlink==1,'desktop-state')
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise Rejected('desktop-busy') from None
            yield
        finally:os.close(fd)

    @contextlib.contextmanager
    def lock(self):
        fd=os.open(self.directory/'wallet.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode & 0o077
                    and info.st_nlink==1,'wallet-lock')
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise Rejected('wallet-busy') from None
            yield
        finally:os.close(fd)

    def read(self,name,*,missing=False):
        # Names are internal constants, never supplied by native messages.
        require(name in ('public.json','pending.sealed','credential.sealed','post.sealed'),'wallet-record')
        try:fd=os.open(self.directory/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        except FileNotFoundError:
            if missing:return None
            raise Rejected('wallet-missing') from None
        except OSError:raise Rejected('wallet-record') from None
        try:
            info=os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o077
                    and info.st_nlink==1 and 0<info.st_size<=MAX_RECORD,'wallet-record')
            return os.read(fd,MAX_RECORD+1)
        finally:os.close(fd)

    def write(self,name,data):
        require(name in ('public.json','pending.sealed','credential.sealed','post.sealed') and type(data) is bytes
                and 0<len(data)<=MAX_RECORD,'wallet-record')
        existing=self.directory/name
        if existing.exists() or existing.is_symlink():self.read(name)
        temporary=self.directory/('.write-'+secrets.token_hex(16))
        try:
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as stream:
                stream.write(data);stream.flush();os.fsync(stream.fileno())
            os.replace(temporary,existing)
            fd=os.open(self.directory,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
        finally:
            if temporary.exists():temporary.unlink()

    @staticmethod
    def tag(secret,salt):
        return hmac.new(secret,b'NOCKAPP/ZKID/WALLET/CHECK/v1\0'+bytes.fromhex(salt),hashlib.sha256).hexdigest()

    def metadata(self):
        data=self.read('public.json',missing=True)
        if data is None:return None
        value=strict_json(data)
        require(set(value)=={'profile','key_id','salt','check'} and value['profile']==PROFILE,'wallet-metadata')
        hex_string(value['key_id'],32);hex_string(value['salt'],32);hex_string(value['check'],64)
        return value

    def secret(self,metadata,service):
        try:
            encoded=service.lookup(metadata['key_id'])
            require(encoded.startswith(PREFIX),'wallet-key-invalid')
            value=hex_string(encoded[len(PREFIX):].decode('ascii'),64)
            raw=bytes.fromhex(value)
            require(hmac.compare_digest(metadata['check'],self.tag(raw,metadata['salt'])),'wallet-key-mismatch')
            return raw
        except (UnicodeError,ValueError):raise Rejected('wallet-key-invalid') from None

    def initialize(self):
        with self.lock():
            service=WalletSecretService();service.ready()
            metadata=self.metadata()
            if metadata is not None:
                self.secret(metadata,service)
                return {'profile':PROFILE,'initialized':True}
            # Incomplete/removed public metadata must not silently rekey a wallet.
            require(not any((self.directory/name).exists() or (self.directory/name).is_symlink()
                            for name in ('pending.sealed','credential.sealed','post.sealed')),'wallet-incomplete')
            raw=secrets.token_bytes(32);key_id=secrets.token_hex(16);salt=secrets.token_hex(16)
            metadata={'profile':PROFILE,'key_id':key_id,'salt':salt,'check':self.tag(raw,salt)}
            stored=False
            try:
                service.store(key_id,PREFIX+raw.hex().encode());stored=True
                self.secret(metadata,service)
                self.write('public.json',canonical(metadata))
                return {'profile':PROFILE,'initialized':True}
            except Exception:
                if stored:
                    try:service.clear(key_id)
                    except Exception:pass
                raise

    @staticmethod
    def cipher(raw,metadata):
        key=HKDF(algorithm=hashes.SHA256(),length=32,salt=bytes.fromhex(metadata['salt']),
                 info=b'NOCKAPP/ZKID/WALLET/AEAD/v1').derive(raw)
        return AESGCM(key)

    def holder_secret(self):
        with self.lock():
            metadata=self.metadata();require(metadata is not None,'wallet-missing')
            return self.secret(metadata,WalletSecretService()).hex()

    def save(self,kind,value):
        require(kind in ('pending','credential','post') and type(value) is dict and 'secret' not in value,'wallet-record')
        plain=canonical(value);require(len(plain)<=MAX_PLAIN,'wallet-record-size')
        with self.lock():
            metadata=self.metadata();require(metadata is not None,'wallet-missing')
            raw=self.secret(metadata,WalletSecretService());nonce=secrets.token_bytes(12)
            aad=canonical({'profile':PROFILE,'key_id':metadata['key_id'],'kind':kind})
            encrypted=self.cipher(raw,metadata).encrypt(nonce,plain,aad)
            self.write(kind+'.sealed',nonce+encrypted)

    def load(self,kind):
        require(kind in ('pending','credential','post'),'wallet-record')
        with self.lock():
            metadata=self.metadata();require(metadata is not None,'wallet-missing')
            raw=self.secret(metadata,WalletSecretService());data=self.read(kind+'.sealed')
            aad=canonical({'profile':PROFILE,'key_id':metadata['key_id'],'kind':kind})
            try:return strict_json(self.cipher(raw,metadata).decrypt(data[:12],data[12:],aad))
            except Exception:raise Rejected('wallet-authentication-failed') from None

    def delete(self,kind):
        require(kind in ('pending','credential','post'),'wallet-record')
        with self.lock():
            metadata=self.metadata();require(metadata is not None,'wallet-missing')
            self.secret(metadata,WalletSecretService())
            if self.read(kind+'.sealed',missing=True) is not None:(self.directory/(kind+'.sealed')).unlink()

    def delete_secret(self):
        with self.lock():
            require(all(self.read(name,missing=True) is None for name in ('pending.sealed','credential.sealed','post.sealed')),
                    'wallet-not-empty')
            metadata=self.metadata();require(metadata is not None,'wallet-missing')
            service=WalletSecretService();self.secret(metadata,service);service.clear(metadata['key_id'])
            (self.directory/'public.json').unlink()
