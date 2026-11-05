"""Pinned private parent startup for preservation and renewal serving images.

Only ciphertext/public files are accepted. Fresh AWS quote and actual TLS key
possession precede IMDSv2, STS and reads of the six selected identity/certificate
heads. No initializer, caller source/account, private-state read, data write,
credential file, automatic retry or credential-bearing output.
"""
import argparse
import base64
import copy
import ctypes
import hashlib
import os
from pathlib import Path
import re
import resource
import socket
import stat
import sys

from aws_transport import AwsJsonClient
from base_managed_storage import DynamoObjects
from parent_boot_channel_v1 import provision_boot_lazy
from domain_transport import _decode
from domain_trust import validate_approval
from issuer_supervisor import CA,tls_context
from operator_identity import StsIdentityClient
from policy import Rejected,canonical,digest,hex_string,require,strict_json
import public_issuer_migration_runtime_v1 as migration
import public_renewal_runtime_v1 as serving
from public_updater_host_v1 import credentials
from public_renewal_sealed_packet_v1 import PROFILE as PACKET
from resume_operator import inspect
from workload_bootstrap import context as identity_context
from workload_ca import scope,certificate_suffix,CERT
from workload_certificates import parse_root,parse_leaf
from workload_identity_ceremony import selection_key,PROFILE as SELECTED

PLAN='nockapp-public-issuer-parent-startup-plan-v1'
RESULT='nockapp-public-issuer-parent-startup-v1'
HOST_ROLE='nockapp-beta-updater-key-host'
DEFAULT_CA=Path('/')/CA


def settings(config,phase):
    require(phase in ('migration','serving'),'parent-startup-phase')
    if phase=='migration':authority=migration.validate_config(config);runtime=config['runtime']
    else:
        authority=serving.validate_config(config);runtime=config
        require(config['profile'] in (serving.PROFILE_SELECTED,serving.PROFILE_BUDGET),'parent-startup-selected-key')
    return runtime,authority


def validate_packet(packet,runtime):
    require(type(packet) is dict and set(packet)=={'profile','issuer_config_sha256','encrypted_secrets'}
        and packet['profile']==PACKET and packet['issuer_config_sha256']==digest(runtime['issuer']),'parent-startup-ciphertext-packet')
    secrets=packet['encrypted_secrets']
    require(type(secrets) is dict and set(secrets)=={'blind-issuer-key','twitterapi-key'},'parent-startup-ciphertext-packet')
    for value in secrets.values():_decode(value,6144)
    require(len(canonical(packet))<=20000,'parent-startup-ciphertext-packet')


def plan(config,approved,packet_sha256,parent,phase):
    runtime,authority=settings(config,phase);validate_approval(approved);hex_string(packet_sha256,64)
    cfg=runtime['issuer']['authority'];account=cfg['table_arn'].split(':')[4]
    require(approved['mode']=='production' and approved['definition_hash']==cfg['namespace']
        and approved['state_authority_sha256']==authority and set(approved['pcrs'])>={'0','1','2'},'parent-startup-approval')
    require(type(parent) is dict and set(parent)=={'instance','role_arn','profile_arn','region'}
        and type(parent['instance']) is str and re.fullmatch(r'i-[0-9a-f]{17}',parent['instance'])
        and parent['region']==cfg['region'] and parent['role_arn']=='arn:aws:iam::'+account+':role/'+HOST_ROLE
        and parent['profile_arn']=='arn:aws:iam::'+account+':instance-profile/'+HOST_ROLE,'parent-startup-parent-role')
    return {'profile':PLAN,'phase':phase,'config_sha256':digest(config),'approval_sha256':digest(approved),
        'packet_sha256':packet_sha256,'parent':copy.deepcopy(parent),'definition_hash':cfg['namespace'],
        'state_authority_sha256':authority,'code_identity':approved['code_identity'],'automatic_retry':False}


def selected_records(client,runtime,authority):
    cfg=runtime['issuer']['authority'];ns=cfg['namespace'];key=runtime['issuer']['kms_key_arn']
    objects=DynamoObjects(client,cfg['table_arn'].split(':table/')[1],ns)
    ca_scope=scope(ns,authority,key);root=parse_root(_decode(runtime['root_certificate'],8192),ns)
    records={}
    for purpose in serving.PURPOSES:
        suffix=selection_key(ns,authority,key,purpose);item=objects._get(suffix)
        require(type(item) is dict and set(item)=={'id','data'} and item['id']==objects.key(suffix)['id']
            and type(item['data']) is dict and set(item['data'])=={'B'},'parent-startup-selected-identity')
        raw=item['data']['B'];selection=strict_json(raw,max_bytes=16384)
        require(canonical(selection)==raw and set(selection)=={'profile','context','key_arn','wrapped_seed','public_key_sha256'}
            and selection['profile']==SELECTED and selection['context']==identity_context(ns,authority,purpose)
            and selection['key_arn']==key,'parent-startup-selected-identity')
        _decode(selection['wrapped_seed'],6144);hex_string(selection['public_key_sha256'],64)
        suffix=certificate_suffix(ca_scope,purpose);item=objects._get(suffix)
        require(type(item) is dict and set(item)=={'id','revision','data'} and item['id']==objects.key(suffix)['id']
            and type(item['data']) is dict and set(item['data'])=={'B'},'parent-startup-selected-certificate')
        raw=item['data']['B'];certificate=strict_json(raw,max_bytes=16384)
        require(canonical(certificate)==raw and set(certificate)=={'profile','scope','purpose','revision','root_sha256',
            'identity_selection_sha256','certificate_der','certificate_sha256'}
            and certificate['profile']==CERT and certificate['scope']==ca_scope and certificate['purpose']==purpose
            and type(certificate['revision']) is int and 1<=certificate['revision']<2**53
            and item['revision']=={'N':str(certificate['revision'])} and certificate['root_sha256']==runtime['root_sha256']
            and certificate['identity_selection_sha256']==digest(selection),'parent-startup-selected-certificate')
        der=_decode(certificate['certificate_der'],8192)
        require(hashlib.sha256(der).hexdigest()==certificate['certificate_sha256'],'parent-startup-selected-certificate')
        # Historical leaf signatures/key bindings are checked even when the leaf
        # expired; only the measured runtime may renew it from the original CA.
        parse_leaf(der,root,ns,purpose,selection['public_key_sha256'])
        records[purpose]={'wrapped_seed':selection['wrapped_seed'],'certificate_der':certificate['certificate_der']}
    return records


def execute(raw,config,approved,packet,value,pin,trace,*,progress=None):
    def mark(stage):
        if progress is not None:progress(stage)
    expected=plan(config,approved,digest(packet),value['parent'],value['phase'])
    require(value==expected and digest(value)==pin,'parent-startup-plan-pin')
    runtime,authority=settings(config,value['phase']);validate_packet(packet,runtime)
    def prepare():
        # This callback runs only after fresh quote verification and TLS1.3
        # possession, inside the parent process. Values never enter argv/logs.
        mark('bootstrap-credentials')
        private=credentials(value['parent']);trace['credentials_obtained']=True
        context=tls_context(DEFAULT_CA)
        mark('bootstrap-caller-identity')
        StsIdentityClient(value['parent']['region'],private,context).verify(value['parent']['role_arn'])
        client=AwsJsonClient('dynamodb',value['parent']['region'],private,context)
        mark('bootstrap-selected-identities')
        envelope={'profile':runtime['profile'],'parent_credentials':private,
            'identities':selected_records(client,runtime,authority),'encrypted_secrets':copy.deepcopy(packet['encrypted_secrets'])}
        mark('bootstrap-envelope-validation');serving.bootstrap(envelope,runtime['profile'])
        if value['phase']=='migration':envelope={'profile':migration.BOOT,'operation':'preserve-and-commit','recovery':envelope}
        trace['delivery_attempted']=True
        mark('bootstrap-delivery-ready')
        return envelope
    mark('bootstrap-channel')
    provision_boot_lazy(raw,approved,prepare)
    mark('bootstrap-acknowledged')
    return {'profile':RESULT,'state':'startup-acknowledged','phase':value['phase'],'plan_sha256':pin,
        'credentials_saved':False,'service_ready':False,'migration_finality_verified':False,'automatic_retry':False}


def read_record(path,*,private=False):
    path=Path(path)
    require(path.is_absolute() and path.suffix=='.json' and '..' not in path.parts
        and not any(p.startswith('.env') for p in path.parts)
        and not any(p.is_symlink() for p in (path,*path.parents)),'parent-startup-record-path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid in (0,os.getuid()) and 0<info.st_size<=65536
            and not info.st_mode&(0o077 if private else 0o022),'parent-startup-record-mode')
        raw=os.read(fd,65537);value=strict_json(raw,max_bytes=65536)
        require(raw in (canonical(value),canonical(value)+b'\n'),'parent-startup-record-canonical');return value
    finally:os.close(fd)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('operation',choices=('inspect','resume','preserve'))
    for name in ('config','approval','packet','plan','plan-sha256'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--port',required=True,type=int);args=parser.parse_args();trace={'delivery_attempted':False}
    try:
        os.umask(0o077);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        require(ctypes.CDLL(None).prctl(4,0,0,0,0)==0,'parent-startup-private-process')
        config=read_record(args.config);approved=read_record(args.approval);packet=read_record(args.packet,private=True);value=read_record(args.plan)
        expected=plan(config,approved,digest(packet),value['parent'],value['phase'])
        require(value==expected and digest(value)==args.plan_sha256,'parent-startup-plan-pin');validate_packet(packet,settings(config,value['phase'])[0])
        require(1<=args.port<=65535,'parent-startup-port')
        require(args.operation=='inspect' or (args.operation,value['phase']) in (('resume','serving'),('preserve','migration')),
            'parent-startup-explicit-operation')
        raw=socket.create_connection(('127.0.0.1',args.port),timeout=10)
        if args.operation=='inspect':result={'profile':RESULT,**inspect(raw,approved),'phase':value['phase'],'service_ready':False}
        else:result=execute(raw,config,approved,packet,value,args.plan_sha256,trace)
        print(canonical({'ok':True,'result':result}).decode());return 0
    except Exception:
        print(canonical({'ok':False,'profile':RESULT,'code':'parent-startup-failed',
            'outcome_unknown':trace['delivery_attempted'],'automatic_retry':False,'credentials_saved':False}).decode());return 1


if __name__=='__main__':raise SystemExit(main())
