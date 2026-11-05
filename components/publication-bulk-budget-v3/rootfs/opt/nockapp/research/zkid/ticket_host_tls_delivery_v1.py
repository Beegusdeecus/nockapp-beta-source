"""Bounded public leaf-certificate delivery through an installer-owned directory.

No private bytes, root/key/config changes, AWS, arbitrary names or auto mkdir.
Writer owns the directory; service readers require the independently pinned UID.
Real bind mounts/UID allocation/read-only enforcement remain installation gates.
"""
import hashlib
import os
from pathlib import Path
import secrets
import stat
import threading

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from policy import require,Rejected
from ticket_host_tls_renewal_v1 import RenewingContext

LIMIT=8192
ROLES=('payment','publication','refund')
FLAGS=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC

def leaf(data):
    require(type(data) is bytes and 0<len(data)<=LIMIT,'host-tls-public-size')
    cert=x509.load_der_x509_certificate(data)
    require(cert.public_bytes(serialization.Encoding.DER)==data
        and not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca,'host-tls-public-leaf')
    return cert

class PublicCertificates:
    def __init__(self,path,owner_uid):
        p=Path(path)
        require(p.is_absolute() and '..' not in p.parts and not any(s.startswith('.env') for s in p.parts)
            and type(owner_uid) is int and (owner_uid==0 or 100<=owner_uid<2**31),'host-tls-public-directory')
        self.path=p;self.owner_uid=owner_uid;self._fd=None;self._lock=threading.RLock()
        fd=os.open('/',FLAGS)
        try:
            for part in p.parts[1:]:
                child=os.open(part,FLAGS,dir_fd=fd);os.close(fd);fd=child;info=os.fstat(fd)
                require(info.st_uid in (0,owner_uid) and (not info.st_mode&0o022
                    or info.st_uid==0 and info.st_mode&stat.S_ISVTX),'host-tls-public-ancestor')
            info=os.fstat(fd)
            require(info.st_uid==owner_uid and stat.S_IMODE(info.st_mode) in (0o700,0o755),'host-tls-public-directory')
            self._fd=fd;fd=None;self._identity=(info.st_dev,info.st_ino)
            self._same()
        except BaseException:
            if self._fd is not None:os.close(self._fd);self._fd=None
            raise
        finally:
            if fd is not None:os.close(fd)
    def __reduce_ex__(self,_):raise TypeError('host-tls-directory-serialization-forbidden')
    def close(self):
        with self._lock:
            if self._fd is not None:os.close(self._fd);self._fd=None
    def _same(self):
        require(self._fd is not None,'host-tls-public-closed')
        held=os.fstat(self._fd);named=os.stat(self.path,follow_symlinks=False)
        require(stat.S_ISDIR(named.st_mode) and (named.st_dev,named.st_ino)==self._identity
            and (held.st_dev,held.st_ino)==self._identity and held.st_uid==self.owner_uid
            and stat.S_IMODE(held.st_mode) in (0o700,0o755),'host-tls-public-directory-rebound')
    def read(self,role):
        with self._lock:
            require(role in ROLES,'host-tls-public-role');self._same()
            fd=os.open(role+'.der',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=self._fd)
            try:
                info=os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_uid==self.owner_uid and info.st_nlink==1
                    and stat.S_IMODE(info.st_mode)==0o644 and 0<info.st_size<=LIMIT,'host-tls-public-file')
                data=os.read(fd,LIMIT+1);after=os.fstat(fd)
                require(len(data)==info.st_size and (after.st_size,after.st_mtime_ns,after.st_ctime_ns)==
                    (info.st_size,info.st_mtime_ns,info.st_ctime_ns),'host-tls-public-file-changed')
                leaf(data);self._same();return data
            finally:os.close(fd)
    def publish(self,role,data):
        require(role in ROLES and os.getuid()==self.owner_uid,'host-tls-public-writer')
        leaf(data) # Never save a private key/blob by mistake, even at a temp name.
        with self._lock:
            self._same();temp='.'+role+'-'+secrets.token_hex(16)+'.tmp';fd=None
            try:
                fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self._fd)
                offset=0
                while offset<len(data):
                    count=os.write(fd,data[offset:]);require(count>0,'host-tls-public-write');offset+=count
                os.fchmod(fd,0o644);os.fsync(fd);self._same()
                os.replace(temp,role+'.der',src_dir_fd=self._fd,dst_dir_fd=self._fd);os.fsync(self._fd)
                return {'certificate_sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
            finally:
                if fd is not None:os.close(fd)
                if fd is not None:
                    try:os.unlink(temp,dir_fd=self._fd)
                    except FileNotFoundError:pass

class CertificatePoller:
    """Public file failures preserve the incumbent; current() still fences expiry."""
    def __init__(self,directory,role,context):
        require(type(directory) is PublicCertificates and role in ROLES and type(context) is RenewingContext
            and context._config['role']==role,'host-tls-poller-scope')
        self._directory=directory;self.role=role;self.context=context
        self._seen=None;self._lock=threading.RLock()
    def refresh(self):
        with self._lock:
            try:
                data=self._directory.read(self.role);pin=hashlib.sha256(data).hexdigest()
                if pin==self._seen:return {'ok':True,'changed':False,'certificate_sha256':pin}
                result=self.context.install(data);self._seen=pin
                return {'ok':True,**result}
            except Exception:return {'ok':False,'changed':False,'code':'host-tls-public-update-unavailable'}
