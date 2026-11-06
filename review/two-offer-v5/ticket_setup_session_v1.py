"""Fresh-key public review -> explicit credential pipes -> sealed packets.

Unfunded keys live only in this process until final encrypted persistence.
Process loss before that requires a NEW session/public review, never recreation
of a funded authority. No resume, automatic retry, cleanup, CA signing, role
creation, service installation/start, original issuer/key access or funding.
"""
import copy
import fcntl
import os
import re
import secrets
import select
import stat
import time
from aws_transport import AwsJsonClient
from policy import canonical,require,strict_json
from provisioning import validate_value
from ticket_aws_credentials_v1 import tls_context
import ticket_new_keys_v1 as fresh
import ticket_packet_store_v1 as storage
from ticket_setup_identity_v1 import identity,session_name

PROFILE='nockapp-ticket-setup-session-v1'
REVIEW='nockapp-ticket-new-key-review-v1'
CREDENTIALS='nockapp-ticket-setup-temporary-credentials-v1'
APPROVAL='reviewed-new-unfunded-host-service-plan'

def descriptors(values):
    require(type(values) is dict and set(values)=={'request','review','credentials'},'ticket-setup-descriptors')
    inodes=[]
    for fd in values.values():
        require(type(fd) is int and fd>=3,'ticket-setup-descriptors')
        info=os.fstat(fd)
        require(stat.S_ISFIFO(info.st_mode) or stat.S_ISSOCK(info.st_mode),'ticket-setup-descriptors')
        require(fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE!=os.O_WRONLY,'ticket-setup-descriptors')
        inodes.append((info.st_dev,info.st_ino));os.set_inheritable(fd,False)
    require(len(set(inodes))==3,'ticket-setup-descriptors')

def read_pipe(fd,limit,seconds):
    end=time.monotonic()+seconds;raw=bytearray()
    while len(raw)<=limit:
        left=end-time.monotonic()
        require(left>0 and select.select([fd],[],[],left)[0],'ticket-setup-input-timeout')
        part=os.read(fd,min(8192,limit+1-len(raw)))
        if not part:break
        raw.extend(part)
    value=strict_json(bytes(raw),max_bytes=limit)
    require(canonical(value)==bytes(raw),'ticket-setup-input-encoding')
    return value

def run(request_pin,fds,output,*,emit,review_timeout=600):
    """Trusted local launcher only. FDs never come from browser messages.

    Request/review are public; credentials remain in a distinct private pipe.
    Public review channel is caller-owned approval, not a self-authenticating
    approval token. No argument or public file may contain credential values.
    """
    result={'profile':PROFILE,'ok':False,'phase':'not-started','outcome_unknown':False,
        'automatic_retry':False,'can_deploy':False,'can_fund':False,'journal_updated':False}
    parent=directory=None;keys=None;sequence=0;path=None
    try:
        storage.digest(request_pin);descriptors(fds)
        require(type(review_timeout) is int and 1<=review_timeout<=3600 and callable(emit),'ticket-setup-arguments')
        path,parent=storage.parent_fd(output)
        require(not storage.exists(parent,path.name),'ticket-setup-session-exists')
        directory=storage.directory(parent,path.name);storage.sync(parent)
        result.update(output=str(path),request_sha256=request_pin,session_id=secrets.token_hex(16))
        def save():
            nonlocal sequence
            result['journal_updated']=False;storage.same_parent(parent,path)
            held=os.fstat(directory);named=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
            require((held.st_dev,held.st_ino)==(named.st_dev,named.st_ino),'ticket-setup-session-rebound')
            require(stat.S_ISDIR(held.st_mode) and held.st_uid==os.getuid()
                and stat.S_IMODE(held.st_mode)==0o700,'ticket-setup-session-mode')
            name='status-'+str(sequence).zfill(4)+'.json'
            storage.write_new(directory,name,canonical({**result,'journal_updated':True}))
            storage.sync(directory);sequence+=1;result['journal_updated']=True
        result['phase']='session-created';save()
        request=read_pipe(fds['request'],4096,10)
        require(storage.sha(canonical(request))==request_pin,'ticket-setup-request-pin')
        fresh.validate_request(request,request_pin) # Never persist a misrouted private packet.
        storage.write_new(directory,'request.json',canonical(request))
        result['phase']='generating-new-unfunded-keys';save()
        keys=fresh.generate(request,request_pin)
        public=keys.public();public_pin=storage.sha(canonical(public))
        storage.write_new(directory,'public-keys.json',canonical(public))
        result.update(phase='awaiting-public-review',public_keys_sha256=public_pin,
            expected_role_sessions={r:session_name(r,result['session_id']) for r in fresh.ROLES})
        save();emit(copy.deepcopy(result))
        review=read_pipe(fds['review'],262144,review_timeout)
        require(type(review) is dict and set(review)=={'profile','session_id','request_sha256','public_keys_sha256',
            'plan','plan_sha256','certificates','approval'} and review['profile']==REVIEW
            and review['approval']==APPROVAL and review['session_id']==result['session_id']
            and review['request_sha256']==request_pin and review['public_keys_sha256']==public_pin,'ticket-setup-review')
        storage.digest(review['plan_sha256'])
        require(type(review['certificates']) is dict and set(review['certificates'])==set(fresh.ROLES),'ticket-setup-review')
        certificates={r:fresh.sealing._decode(review['certificates'][r],8192) for r in fresh.ROLES}
        # Includes TLS key/leaf/root chain and generated authority bindings,
        # using locally generated keys only, BEFORE credentials are consumed.
        require(keys.admit_review(review['plan'],review['plan_sha256'],certificates),'ticket-setup-review')
        storage.write_new(directory,'review.json',canonical(review))
        result.update(phase='awaiting-temporary-setup-credentials',plan_sha256=review['plan_sha256']);save()
        emit(copy.deepcopy(result))
        packet=read_pipe(fds['credentials'],32768,10)
        require(type(packet) is dict and set(packet)=={'profile','session_id','plan_sha256','roles'}
            and packet['profile']==CREDENTIALS and packet['session_id']==result['session_id']
            and packet['plan_sha256']==review['plan_sha256'] and type(packet['roles']) is dict
            and set(packet['roles'])==set(fresh.ROLES),'ticket-setup-credentials')
        credentials={r:validate_value('managed-writer-credentials',packet['roles'][r]) for r in fresh.ROLES}
        require(len({v['access_key_id'] for v in credentials.values()})==3
            and all(v['expires_at']>=int(time.time())+300 for v in credentials.values()),'ticket-setup-credentials')
        result.update(phase='checking-setup-role-identities',verified_roles=[]);save()
        for role in fresh.ROLES:
            cfg=review['plan']['roles'][role]['backend'];records=cfg['records']
            checked=identity(credentials[role],records['region'],records['account_id'],role,result['session_id'])
            result['verified_roles'].append({'role':role,**checked});save()
        clients={r:AwsJsonClient('kms',review['plan']['roles'][r]['backend']['records']['region'],credentials[r],tls_context()) for r in fresh.ROLES}
        result.update(phase='encrypted-preparation-intent',outcome_unknown=True);save()
        prepared=keys.prepare(review['plan'],review['plan_sha256'],certificates,clients=clients,output=path/'sealed')
        result.update(preparation=prepared,ok=prepared['ok'],outcome_unknown=prepared['outcome_unknown'],
            phase='encrypted-packets-prepared' if prepared['ok'] else 'encrypted-preparation-failed')
        save();emit(copy.deepcopy(result));return result
    except BaseException:
        result.update(ok=False,error='ticket-setup-session-failed')
        if directory is not None:
            try:save()
            except BaseException:result.update(journal_updated=False,outcome_unknown=True)
        return result
    finally:
        if keys is not None:keys.close()
        if directory is not None:os.close(directory)
        if parent is not None:os.close(parent)

