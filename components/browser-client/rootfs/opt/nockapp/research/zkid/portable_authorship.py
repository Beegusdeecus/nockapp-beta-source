"""User-controlled encrypted authorship-secret backup; local CLI only.

Passphrases use the local terminal, never argv or browser native messages. A
backup contains no credential signature: restore that file too or renew through
the source ceremony. No plaintext secret file, automatic overwrite or rotation.
"""
import base64
import getpass
import os
from pathlib import Path
import secrets
import stat
import sys
import time
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from authorship_desktop_v5 import AuthorshipDesktopV5
from policy import canonical,hex_string,require,strict_json,Rejected

PROFILE='nockapp-portable-authorship-secret-v1'
KDF={'name':'scrypt','n':131072,'r':8,'p':1,'length':32}
FORMAT='bls12-381-scalar-canonical-little-endian-v1'
MAX_BYTES=4096

def _password(value):
    require(type(value) is str and 16<=len(value.encode('utf-8'))<=1024,'backup-passphrase-length')
    return value.encode('utf-8')

def _b64(v):return base64.b64encode(v).decode('ascii')
def _raw(v,limit):
    require(type(v) is str and len(v)<=4*((limit+2)//3),'backup-encoding')
    try:r=base64.b64decode(v,validate=True)
    except Exception:raise Rejected('backup-encoding') from None
    require(len(r)<=limit and _b64(r)==v,'backup-encoding');return r

def _key(password,salt):return Scrypt(salt=salt,length=32,n=KDF['n'],r=KDF['r'],p=KDF['p']).derive(_password(password))

def backup(author,passphrase,approve_export):
    require(approve_export is True and isinstance(author,AuthorshipDesktopV5),'consent-required')
    _password(passphrase)
    with author.transaction():
        record=author._load();scalar=record['identity']['scalar']
        salt=secrets.token_bytes(16);nonce=secrets.token_bytes(12)
        header={'profile':PROFILE,'format':FORMAT,'kdf':dict(KDF),'salt':_b64(salt),'nonce':_b64(nonce)}
        plain=canonical({'profile':PROFILE,'format':FORMAT,'scalar':scalar})
        encrypted=AESGCM(_key(passphrase,salt)).encrypt(nonce,plain,canonical(header))
        return canonical({**header,'ciphertext':_b64(encrypted)})

def restore(author,data,passphrase,now,approve_import):
    require(approve_import is True and isinstance(author,AuthorshipDesktopV5),'consent-required')
    value=strict_json(data,max_bytes=MAX_BYTES)
    require(type(value) is dict and set(value)=={'profile','format','kdf','salt','nonce','ciphertext'}
        and value['profile']==PROFILE and value['format']==FORMAT and value['kdf']==KDF
        and canonical(value)==data,'backup-format')
    salt=_raw(value['salt'],16);nonce=_raw(value['nonce'],12);encrypted=_raw(value['ciphertext'],1024)
    require(len(salt)==16 and len(nonce)==12 and len(encrypted)>16,'backup-format')
    header={k:v for k,v in value.items() if k!='ciphertext'}
    try:plain=AESGCM(_key(passphrase,salt)).decrypt(nonce,encrypted,canonical(header))
    except Rejected:raise
    except Exception:raise Rejected('backup-authentication-failed') from None
    record=strict_json(plain,max_bytes=1024)
    require(type(record) is dict and set(record)=={'profile','format','scalar'} and record['profile']==PROFILE
        and record['format']==FORMAT,'backup-format');hex_string(record['scalar'],64)
    # The native worker rejects zero/noncanonical scalars and validates the
    # restored key before the destination wallet can acquire any secret record.
    root=author.native.call('pseudonym',secret=record['scalar'],scope={'kind':'signing-identity'})['pseudonym']
    with author.transaction():
        if author.wallet.read('credential.sealed',missing=True) is not None:
            require(author._load()['root']==root,'backup-existing-key-conflict')
            return author.status() # Same-key lost-reply recovery never overwrites the wallet.
        require(author.wallet.metadata() is None and all(author.wallet.read(n,missing=True) is None
            for n in ('credential.sealed','post.sealed','pending.sealed')),'backup-destination-not-empty')
        # A configured prior identity/holder must agree, even if expired. Never
        # inherit an incumbent credential by importing an unrelated new key.
        for old in author.previous_authors:
            with old.transaction():
                if old.wallet.read('credential.sealed',missing=True) is not None:
                    require(old._load()['root']==root,'backup-existing-key-conflict')
        for source in author.legacy_sources:
            with source.transaction():
                require(source.wallet.read('pending.sealed',missing=True) is None,'author-legacy-recovery-required')
                if source.wallet.read('credential.sealed',missing=True) is not None:
                    from authorship_desktop import held_scalar
                    r=source._check(source.wallet.load('credential'))
                    converted=author.native.call('normalize-held-scalar',scalar=held_scalar(r['credential']))
                    require(converted['root']==root,'backup-existing-key-conflict')
        return author._create({'scalar':record['scalar']},root,{'kind':'restored-portable-secret','format':FORMAT},now)

def _path(value):
    p=Path(value)
    require(p.is_absolute() and '..' not in p.parts and not any(v.startswith('.env') for v in p.parts)
        and not any(v.is_symlink() for v in (p,*p.parents)),'backup-file')
    return p

def read_file(path,*,private=True):
    p=_path(path);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_uid in (0,os.getuid())
            and not st.st_mode&(0o077 if private else 0o022) and 0<st.st_size<=MAX_BYTES,'backup-file')
        raw=os.read(fd,MAX_BYTES+1);require(len(raw)==st.st_size,'backup-file');return raw
    finally:os.close(fd)

def write_backup(path,data):
    p=_path(path);require(type(data) is bytes and 0<len(data)<=MAX_BYTES,'backup-file')
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
        directory=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
    except Exception:
        p.unlink(missing_ok=True);raise

def main(argv=None):
    import argparse
    parser=argparse.ArgumentParser(description='Local encrypted authorship-secret backup/restore; no credential or wallet-address authority transfer.')
    parser.add_argument('action',choices=('backup','restore'));parser.add_argument('--wallet',required=True)
    parser.add_argument('--binding',required=True);parser.add_argument('--file',required=True)
    args=parser.parse_args(argv)
    try:
        require(sys.stdin.isatty() and sys.stderr.isatty(),'backup-local-terminal-required')
        config=strict_json(read_file(args.binding,private=False),max_bytes=MAX_BYTES)
        if args.action=='backup':require(_path(args.wallet).is_dir(),'backup-wallet-missing')
        author=AuthorshipDesktopV5(_path(args.wallet),config)
        phrase=getpass.getpass('Backup passphrase (use a strong unique phrase): ')
        if args.action=='backup':
            require(phrase==getpass.getpass('Repeat passphrase: '),'backup-passphrase-mismatch')
            write_backup(args.file,backup(author,phrase,True))
        else:restore(author,read_file(args.file),phrase,int(time.time()),True)
        print('Encrypted authorship backup complete.' if args.action=='backup' else 'Authorship secret restored. Credentials may need restoration or renewal.')
        return 0
    except Exception:
        print('Backup/restore could not complete. Existing identities were not replaced.');return 1

if __name__=='__main__':raise SystemExit(main())
