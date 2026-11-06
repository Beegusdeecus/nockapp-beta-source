"""Internal first-setup coordinator: reviewed private pipes -> encrypted storage.

No CLI, key generation, ambient credentials, original issuer material, live
installation, permission changes, resume, rollback or retry. A reviewed caller
supplies public plan/pin, three already-open private pipes and explicit clients.
"""
import copy
import fcntl
import os
import secrets
import stat
import threading

from policy import canonical,require,Rejected
import ticket_key_seal_v1 as seal
import ticket_packet_store_v1 as storage

PROFILE='nockapp-ticket-key-setup-v1'
ROLES=storage.ROLES

def validate_public(plan,expected):
    """Full public group/scope admission before any credentials or pipe reads."""
    import re
    storage.digest(expected)
    require(type(plan) is dict and set(plan)=={'profile','purpose','roles'}
        and plan['profile']==PROFILE and plan['purpose']=='new-host-service-keys'
        and len(canonical(plan))<=262144 and storage.sha(canonical(plan))==expected,
        'ticket-key-setup-plan')
    require(type(plan['roles']) is dict and set(plan['roles'])==set(ROLES),'ticket-key-setup-roles')
    configs=[]
    for role in ROLES:
        value=plan['roles'][role]
        require(type(value) is dict and set(value)=={'backend','backend_sha256','kms_key_arn'},'ticket-key-setup-role')
        cfg=seal.validate(value['backend'],value['backend_sha256'])
        prefix='arn:aws:kms:'+cfg['records']['region']+':'+cfg['records']['account_id']+':key/'
        require(type(value['kms_key_arn']) is str and re.fullmatch(re.escape(prefix)+
            r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value['kms_key_arn']),'ticket-seal-kms-scope')
        require(cfg['role']==role,'ticket-key-setup-role');configs.append(cfg)
    first=configs[0]
    require(all(c['offer_sha256']==first['offer_sha256'] and c['key_bindings']==first['key_bindings']
        and c['ticket_native_sha256']==first['ticket_native_sha256'] and c['tls']['root_sha256']==first['tls']['root_sha256']
        and all(c['records'][k]==first['records'][k] for k in ('account_id','region')) for c in configs)
        and len({c['tls']['key_sha256'] for c in configs})==3,'ticket-key-setup-split-config')
    payment,publication,refund=configs
    purchase=payment['records']['purchase_bucket']
    private={purchase,publication['records']['ledger_bucket'],refund['records']['ledger_bucket']}
    require(refund['records']['purchase_bucket']==purchase
        and purchase not in (publication['records']['ledger_bucket'],refund['records']['ledger_bucket'])
        and publication['origin']['bucket'] not in private,'ticket-key-setup-storage-scope')
    return configs

def validate(plan,expected,descriptors,clients):
    validate_public(plan,expected)
    require(type(descriptors) is dict and type(clients) is dict
        and set(descriptors)==set(clients)==set(ROLES),'ticket-key-setup-roles')
    for role in ROLES:
        value=plan['roles'][role]
        seal.public_scope(value['backend'],value['backend_sha256'],value['kms_key_arn'],clients[role])
        fd=descriptors[role]
        require(type(fd) is int and fd>=0,'ticket-key-setup-pipe')
        info=os.fstat(fd);require(stat.S_ISFIFO(info.st_mode) or stat.S_ISSOCK(info.st_mode),'ticket-key-setup-pipe')
    require(len(set(descriptors.values()))==3,'ticket-key-setup-pipe')

def seal_bytes(value,data,client):
    """Private in-memory relay into the existing independently tested sealer."""
    read,write=os.pipe();errors=[]
    def deliver():
        try:
            with os.fdopen(write,'wb') as stream:stream.write(data)
        except Exception:errors.append(True)
    writer=threading.Thread(target=deliver,daemon=True);started=False
    try:
        writer.start();started=True
        return seal.seal(value['backend'],value['backend_sha256'],value['kms_key_arn'],read,client=client)
    finally:
        os.close(read)
        if started:
            writer.join(timeout=10)
            require(not writer.is_alive() and not errors,'ticket-key-setup-private-relay')
        else:os.close(write)

def prepare(plan,expected,descriptors,*,clients,output):
    # Freeze public mappings; a trusted caller supplies the open FDs/clients.
    plan=copy.deepcopy(plan);descriptors=dict(descriptors);clients=dict(clients)
    validate(plan,expected,descriptors,clients)
    path,parent=storage.parent_fd(output);lock=stage_fd=None;result=None
    try:
        require(not storage.exists(parent,path.name),'ticket-key-setup-output-exists')
        lock=os.open('.nockapp-ticket-setup-'+path.name+'.lock',
            os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,0o600,dir_fd=parent)
        info=os.fstat(lock)
        require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1
            and info.st_size==0 and stat.S_IMODE(info.st_mode)==0o600,'ticket-key-setup-lock')
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        require(not storage.exists(parent,path.name),'ticket-key-setup-output-exists')
        storage.same_parent(parent,path)
        stage='.nockapp-ticket-key-setup-'+secrets.token_hex(16)
        result={'profile':PROFILE,'ok':False,'plan_sha256':expected,'output':str(path),
            'stage':str(path.parent/stage),'phase':'staging','validated_roles':[],
            'kms_attempts':[],'sealed_sha256':{},'kms_outcome_unknown':False,
            'outcome_unknown':False,'automatic_retry':False,'journal_updated':False}
        def save():
            result['journal_updated']=False;name='status-'+secrets.token_hex(16)+'.tmp'
            storage.write_new(stage_fd,name,storage.canonical({**result,'journal_updated':True}))
            os.replace(name,'status.json',src_dir_fd=stage_fd,dst_dir_fd=stage_fd);storage.sync(stage_fd)
            result['journal_updated']=True
        try:
            stage_fd=storage.directory(parent,stage);storage.sync(parent)
            storage.write_new(stage_fd,'plan.json',canonical(plan));storage.sync(stage_fd);save()
            seal.harden_process();private={}
            for role in ROLES:
                value=plan['roles'][role]
                private[role]=seal.checked_body(value['backend'],value['backend_sha256'],seal.read_private(descriptors[role]))
                result['validated_roles'].append(role)
            result['phase']='all-private-inputs-validated';save()
            packets={};pins={}
            for role in ROLES:
                value=plan['roles'][role]
                storage.same_parent(parent,path)
                require(not storage.exists(parent,path.name),'ticket-key-setup-output-exists')
                result.update(phase='sealing',kms_outcome_unknown=True,outcome_unknown=True)
                result['kms_attempts'].append(role);save()
                encrypted=seal_bytes(value,private.pop(role),clients[role])
                pins[role]={'sha256':storage.sha(encrypted),'backend_sha256':value['backend_sha256'],'kms_key_arn':value['kms_key_arn']}
                storage.write_new(stage_fd,role+'.json',encrypted);storage.sync(stage_fd)
                packets[role]=encrypted;result['sealed_sha256'][role]=pins[role]['sha256']
                result.update(kms_outcome_unknown=False,outcome_unknown=False);save()
            result.update(phase='storage-intent',outcome_unknown=True);save()
            result['storage']=storage.store(packets,pins,path)
            require(result['storage']['ok'],'ticket-key-setup-storage-failed')
            result.update(phase='prepared',ok=True,outcome_unknown=False);save()
            return result
        except Exception:
            journal_failed=not result['journal_updated']
            result.update(ok=False,error='ticket-key-setup-failed')
            if 'storage' in result:
                result['outcome_unknown']=result['kms_outcome_unknown'] or result['storage']['outcome_unknown'] or journal_failed
            if stage_fd is not None:
                try:save()
                except Exception:result.update(journal_updated=False,outcome_unknown=True)
            return result
    finally:
        if stage_fd is not None:os.close(stage_fd)
        if lock is not None:os.close(lock)
        os.close(parent)
