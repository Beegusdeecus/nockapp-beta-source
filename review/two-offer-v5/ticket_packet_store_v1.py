"""Durable first-write storage of exactly three encrypted host-key packets.

Standard library only. No keys, credentials, AWS, decryption, service changes,
replacement, cleanup or retry. Public pins are trusted setup inputs. A private
same-owner parent is required; stages and uncertain outcomes remain inspectable.
"""
import base64
import ctypes
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat

PROFILE='nockapp-ticket-packet-store-v1'
ROLES=('payment','publication','refund')
FLAGS=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC

def require(value):
    if not value:raise ValueError('ticket-packet-store-rejected')
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(data):return hashlib.sha256(data).hexdigest()
def digest(value):require(type(value) is str and re.fullmatch('[0-9a-f]{64}',value) and int(value,16)>0)
def record(data):
    def pairs(rows):
        value={}
        for k,v in rows:require(k not in value);value[k]=v
        return value
    value=json.loads(data,object_pairs_hook=pairs,parse_constant=lambda _:require(False))
    require(canonical(value)==data);return value

def validate(packets,pins):
    require(type(packets) is dict and type(pins) is dict and set(packets)==set(pins)==set(ROLES))
    for role in ROLES:
        data=packets[role];expected=pins[role]
        require(type(data) is bytes and 0<len(data)<=100000 and type(expected) is dict
            and set(expected)=={'sha256','backend_sha256','kms_key_arn'})
        digest(expected['sha256']);digest(expected['backend_sha256'])
        require(sha(data)==expected['sha256'] and type(expected['kms_key_arn']) is str
            and re.fullmatch(r'arn:aws:kms:[a-z]{2}-[a-z]+-[1-9]:[0-9]{12}:key/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',expected['kms_key_arn']))
        value=record(data)
        require(type(value) is dict and set(value)=={'profile','role','backend_sha256','kms_key_arn','wrapped_key','nonce','ciphertext'}
            and value['profile']=='nockapp-ticket-sealed-boot-v1' and value['role']==role
            and value['backend_sha256']==expected['backend_sha256'] and value['kms_key_arn']==expected['kms_key_arn'])
        for field,low,high in [('wrapped_key',1,6144),('nonce',12,12),('ciphertext',17,65552)]:
            text=value[field];require(type(text) is str and len(text)<=4*((high+2)//3))
            raw=base64.b64decode(text,validate=True)
            require(low<=len(raw)<=high and base64.b64encode(raw).decode('ascii')==text)

def parent_fd(output):
    path=Path(output)
    require(path.is_absolute() and '..' not in path.parts and not any(v.startswith('.env') for v in path.parts)
        and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,79}',path.name))
    fd=os.open('/',FLAGS)
    try:
        for part in path.parent.parts[1:]:
            new=os.open(part,FLAGS,dir_fd=fd);os.close(fd);fd=new
            info=os.fstat(fd)
            require(info.st_uid in (0,os.getuid()) and
                (not info.st_mode&0o022 or bool(info.st_mode&stat.S_ISVTX)))
        info=os.fstat(fd)
        require(info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700)
        return path,fd
    except BaseException:
        os.close(fd);raise

def exists(fd,name):
    try:os.stat(name,dir_fd=fd,follow_symlinks=False);return True
    except FileNotFoundError:return False
def same_parent(fd,path):
    _,current=parent_fd(path)
    try:
        a=os.fstat(fd);b=os.fstat(current)
        require((a.st_dev,a.st_ino)==(b.st_dev,b.st_ino))
    finally:os.close(current)
def sync(fd):os.fsync(fd)
def directory(fd,name):
    os.mkdir(name,mode=0o700,dir_fd=fd)
    new=os.open(name,FLAGS,dir_fd=fd)
    try:os.fchmod(new,0o700);sync(new);return new
    except BaseException:os.close(new);raise
def write_new(fd,name,data):
    out=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=fd)
    try:
        os.fchmod(out,0o600);offset=0
        while offset<len(data):
            size=os.write(out,data[offset:]);require(size>0);offset+=size
        sync(out);info=os.fstat(out)
        require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1
            and stat.S_IMODE(info.st_mode)==0o600 and info.st_size==len(data))
    finally:os.close(out)
def commit(source_fd,dest_fd,name):
    fn=ctypes.CDLL(None,use_errno=True).renameat2
    fn.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint];fn.restype=ctypes.c_int
    if fn(source_fd,b'packets',dest_fd,os.fsencode(name),1)!=0:
        raise OSError(ctypes.get_errno(),'ticket-packet-store-commit-failed')
def verify(fd,packets):
    require(set(os.listdir(fd))=={r+'.json' for r in ROLES})
    for role,data in packets.items():
        inp=os.open(role+'.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
        try:
            info=os.fstat(inp)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1
                and stat.S_IMODE(info.st_mode)==0o600 and info.st_size==len(data))
            with os.fdopen(os.dup(inp),'rb') as stream:require(stream.read(100001)==data)
        finally:os.close(inp)

def store(packets,pins,output):
    """Preflight errors raise; after staging returns a fixed public result.

    A false/unknown result is a review stop. Never retry automatically or remove
    its stage: commit intent may be durable even if its acknowledgement was lost.
    Only a new output directory is committed, using RENAME_NOREPLACE.
    """
    require(type(packets) is dict and type(pins) is dict)
    packets=packets.copy();pins={k:v.copy() if type(v) is dict else v for k,v in pins.items()}
    validate(packets,pins)
    require(hasattr(ctypes.CDLL(None),'renameat2'))
    path,parent=parent_fd(output);stage_fd=packet_fd=None;result=None
    try:
        require(not exists(parent,path.name))
        identifier=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+secrets.token_hex(16)
        stage='.nockapp-ticket-packets-'+identifier
        result={'profile':PROFILE,'ok':False,'output':str(path),'stage':str(path.parent/stage),
            'packet_sha256':{r:pins[r]['sha256'] for r in ROLES},'phase':'staging-create-intent',
            'commit_attempted':False,'outcome_unknown':False,'automatic_retry':False,'journal_updated':False}
        def save():
            result['journal_updated']=False
            temp='status-'+secrets.token_hex(16)+'.tmp'
            payload={**result,'journal_updated':True}
            write_new(stage_fd,temp,canonical(payload))
            os.replace(temp,'status.json',src_dir_fd=stage_fd,dst_dir_fd=stage_fd);sync(stage_fd)
            result['journal_updated']=True
        try:
            stage_fd=directory(parent,stage);sync(parent)
            result['phase']='staging';save()
            packet_fd=directory(stage_fd,'packets');sync(stage_fd)
            for role in ROLES:write_new(packet_fd,role+'.json',packets[role])
            sync(packet_fd);verify(packet_fd,packets)
            same_parent(parent,path)
            result.update(phase='commit-intent',commit_attempted=True,outcome_unknown=True);save()
            commit(stage_fd,parent,path.name);sync(stage_fd);sync(parent)
            final=os.stat(path.name,dir_fd=parent,follow_symlinks=False);original=os.fstat(packet_fd)
            require((final.st_dev,final.st_ino)==(original.st_dev,original.st_ino))
            verify(packet_fd,packets)
            same_parent(parent,path)
            result.update(phase='committed',ok=True,outcome_unknown=False);save()
            return result
        except Exception:
            result.update(ok=False,error='ticket-packet-store-failed',
                outcome_unknown=result['commit_attempted'])
            if stage_fd is not None:
                try:save()
                except Exception:result['journal_updated']=False
            return result
    finally:
        if packet_fd is not None:os.close(packet_fd)
        if stage_fd is not None:os.close(stage_fd)
        os.close(parent)
