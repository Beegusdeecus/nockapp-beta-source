"""Dedicated public-post Native Messaging candidate. No installed registration.

Fixed installer-owned trust/path/address and exact browser admission precede stdin.
No cookies, headers, caller sessions/keys/trust/URLs/endpoints or proof verifier.
"""
import os
from pathlib import Path
import re
import stat
import struct
import sys

from domain_bridge import DomainBridge
from domain_pipeline import PROFILE as CREDENTIAL
from domain_trust import validate_approval
from domain_transport import validate_endpoint
from post_holder import PostHolder,validate_pair
from post_scope import PROFILE as POST_REFERENCE
from policy import Rejected,canonical,hex_string,require,strict_json,timestamp

PROFILE='nockapp-zkid-public-post-native-v1'
HOST='com.nockapp.zkid'
ROOT=Path(__file__).resolve().parent
MAX_MESSAGE=131072
MAX_MESSAGES=32
REQUIRED={'domain_native.py','domain_native_entrypoint.py','domain_bridge.py','domain_desktop.py',
          'domain_pipeline.py','domain_transport.py','domain_trust.py','policy.py','wallet.py',
          'domain_candidate.py','domain-source.lock.json','trust.py',
          'post_holder.py','post_transport.py','post_remote_transport.py','post_scope.py','domain_post_rpc.py','domain_authority.py',
          'domain_state.py','budget.py','credential.py',
          'domain-crypto/target/debug/nockapp-zkid-domain-research'}
BASE_REQUIRED={'base_desktop.py','base_enrollment.py','base_client.py','base_evm.py','base_protocol.py','base_rpc.py',
               'base_service.py','base_state.py','base_transport.py','domain_issuer.py',
               'domain_post_authority.py','domain_posts.py','enclave_nsm.py','local/base-tools/cast'}
BUNDLE_REQUIRED=BASE_REQUIRED|{'bundle_desktop.py','bundle_disk_cache.py','bundle_reader.py','bundle_acceptance.py',
    'bundle_service.py','bundle_transport.py','public_bundle.py','public_storage.py','public_s3.py','public_s3_endpoints.py','count_policy.py',
    'aws_transport.py','provisioning.py','service_admission.py','setup_aws_sdk.py','aws-sdk.lock.json','workload_sessions.py'}
COUNT_REQUIRED={'count_desktop.py','count_enrollment.py','count_pipeline.py','count_protocol.py','count_state.py',
    'count_service.py','count_transport.py','count_receipts.py','base_finality.py',
    'local/count-native/debug/nockapp-zkid-count-v2'}


def configuration():
    import hashlib
    path=ROOT/'domain-native-config.json'
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid in (0,os.getuid()) and not info.st_mode&0o022
                and 0<info.st_size<=65536,'native-config')
        data=os.read(fd,65537);require(len(data)<=65536,'native-config')
    finally:os.close(fd)
    value=strict_json(data,max_bytes=65536)
    if value.get('profile') in ('nockapp-installed-public-native-v6','nockapp-installed-public-native-v7','nockapp-installed-public-direct-v1','nockapp-installed-public-renewal-v1'):
        from public_installation import validate as validate_public
        return validate_public(value)
    base={'profile','browser','issuer_approval','wallet_directory','files_sha256'}
    shared={'base_approval','base_chain','base_directory'}
    bundles={'bundle_approval','bundle_chain','bundle_directory'}
    counts={'count_approval','count_wallet_directory'}
    keys=set(value)
    if keys&shared:
        require(shared<=keys,'native-config');keys-=shared
    if keys&bundles:
        require(bundles<=keys and not value.keys()&shared,'native-config');keys-=bundles
    if keys&counts:
        require(counts<=keys and bundles<=value.keys(),'native-config');keys-=counts
    require(keys in (base|{'issuer_port'},base|{'issuer_endpoint'},
                           base|{'issuer_port','verifier_approval'},base|{'issuer_endpoint','verifier_approval'})
            and value['profile']==PROFILE,'native-config')
    validate_approval(value['issuer_approval'])
    if 'issuer_endpoint' in value:validate_endpoint(value['issuer_endpoint'])
    else:require(type(value['issuer_port']) is int and 1<=value['issuer_port']<=65535,'native-config')
    directory=value['wallet_directory']
    require(type(directory) is str and Path(directory).is_absolute() and '..' not in Path(directory).parts
            and not any(p.startswith('.env') for p in Path(directory).parts),'native-config')
    pins=value['files_sha256'];required=REQUIRED|(BASE_REQUIRED if 'base_approval' in value else set())
    if 'bundle_approval' in value:
        required|=BUNDLE_REQUIRED
        if value['bundle_approval'].get('identity',{}).get('count_native_sha256') is not None:required|=COUNT_REQUIRED
    require(type(pins) is dict and set(pins)==required,'native-config')
    for name,sha in pins.items():
        hex_string(sha,64)
        # Logical pin names remain stable across source/private and compiled
        # releases; the loaded executable fixes the physical artifact layout.
        physical=name[:-3]+'.so' if __file__.endswith('.so') and name.endswith('.py') else name
        source=ROOT/physical
        require(not any(p.is_symlink() for p in [source,*source.parents]) and source.is_file()
                and hashlib.sha256(source.read_bytes()).hexdigest()==sha,'native-code-changed')
    if 'verifier_approval' in value:
        validate_pair(value['issuer_approval'],value['verifier_approval'],pins['domain-crypto/target/debug/nockapp-zkid-domain-research'])
    if 'base_approval' in value:
        from base_desktop import validate_chain
        from base_transport import validate_approval as base_approval
        approved=base_approval(value['base_approval']);validate_chain(value['base_chain'],approved)
        require(approved['identity']['native_sha256']==pins['domain-crypto/target/debug/nockapp-zkid-domain-research'],
            'native-config')
        require(approved['identity']['definition_hash']==value['issuer_approval']['definition_hash'],'native-config')
        directory=value['base_directory']
        require(type(directory) is str and Path(directory).is_absolute() and '..' not in Path(directory).parts
            and not any(p.startswith('.env') for p in Path(directory).parts)
            and not Path(directory).is_relative_to(Path(value['wallet_directory']))
            and not Path(value['wallet_directory']).is_relative_to(Path(directory)),'native-config')
    if 'bundle_approval' in value:
        from bundle_transport import validate_approval as bundle_approval
        from bundle_desktop import validate_chain as bundle_chain
        approved=bundle_approval(value['bundle_approval']);bundle_chain(value['bundle_chain'],approved)
        require(approved['identity']['native_sha256']==pins['domain-crypto/target/debug/nockapp-zkid-domain-research']
            and approved['identity']['definition_hash']==value['issuer_approval']['definition_hash'],'native-config')
        paths=[Path(value['wallet_directory']),Path(value['bundle_directory'])]
        if approved['identity']['count_native_sha256'] is not None:
            require(approved['identity']['count_native_sha256']==pins['local/count-native/debug/nockapp-zkid-count-v2'],'native-config')
        if 'count_approval' in value:
            from count_service import validate_count_approval
            count=validate_count_approval(value['count_approval'])
            require(count['native_sha256']==approved['identity']['count_native_sha256'],'native-config')
            paths.append(Path(value['count_wallet_directory']))
        for i,path in enumerate(paths):
            require(path.is_absolute() and '..' not in path.parts and not any(p.startswith('.env') for p in path.parts)
                and not any(path.is_relative_to(p) or p.is_relative_to(path) for p in paths[:i]),'native-config')
    return value


def authorize(arguments,browser):
    require(type(browser) is dict,'native-origin')
    if set(browser)=={'kind','origin'} and browser['kind']=='chrome':
        origin=browser['origin']
        require(type(origin) is str and re.fullmatch(r'chrome-extension://[a-p]{32}/',origin)
                and arguments==[origin],'native-origin')
    elif set(browser)=={'kind','extension_id','manifest_path'} and browser['kind']=='firefox':
        ident=browser['extension_id'];manifest=browser['manifest_path']
        require(type(ident) is str and re.fullmatch(r'[A-Za-z0-9_.@{}-]{1,128}',ident)
                and type(manifest) is str and Path(manifest).is_absolute()
                and arguments==[manifest,ident],'native-origin')
    else:raise Rejected('native-origin')


class LazyBridge:
    """Installer-created bridge; ordinary native operations never open a wallet."""
    def __init__(self,factory):self._factory=factory;self._value=None
    def __getattr__(self,name):
        if self._value is None:self._value=self._factory()
        return getattr(self._value,name)


class NativeApplication:
    def __init__(self,bridge,posts=None,base=None,*,bundle=None,counts=None,authorship=None,
                 authored_bundle=None,authored_counts=None,public_app=None):
        self._bridge=bridge;self._posts=posts;self._base=base;self._bundle=bundle;self._counts=counts;self._authorship=authorship
        require(authored_counts is None or authored_bundle is not None,'author-native-unavailable')
        self._authored=(NativeApplication(None,bundle=authored_bundle,counts=authored_counts)
            if authored_bundle is not None else None)
        self._public=public_app
        self._legacy_readonly=authored_bundle is not None or public_app is not None

    def dispatch(self,message):
        ident='0'*32;op=None
        try:
            require(type(message) is dict and set(message)=={'profile','id','operation','body'}
                    and message['profile']==PROFILE,'message-schema')
            hex_string(message['id'],32);ident=message['id'];op=message['operation'];body=message['body']
            require(type(op) is str and type(body) is dict,'message-schema')
            if op.startswith('public-'):
                require(self._public is not None,'public-native-unavailable')
                result=self._public.dispatch(op,body)
            elif op.startswith('authored-'):
                action=op[len('authored-'):]
                require(self._authored is not None and (action.startswith('bundle-') or action.startswith('count-')),
                    'author-native-unavailable')
                if self._public is not None:
                    require(action not in ('bundle-publish','bundle-renew','bundle-address-request','bundle-address-result','count-begin'),
                        'legacy-publication-disabled')
                    if action=='bundle-recover':action='bundle-check-existing'
                return self._authored.dispatch({**message,'operation':action})
            elif op.startswith('authorship-'):
                require(self._authorship is not None,'author-native-unavailable')
                result=self._authorship.dispatch(op,body)
            elif op=='bundle-capabilities':
                require(not body,'message-schema')
                result=self._bundle.capabilities() if self._bundle is not None else {'configured':False,'experimental':True}
            elif op.startswith('bundle-'):
                require(self._bundle is not None,'bundle-service-unavailable')
                require(self._public is None or op not in ('bundle-address-request','bundle-address-result'),
                    'legacy-publication-disabled')
                if op=='bundle-initialize-identity':
                    require(set(body)=={'approve_private_key_setup'} and body['approve_private_key_setup'] is True,'consent-required')
                    result=self._bundle.initialize_identity(True)
                elif op=='bundle-history-request':
                    require(set(body)=={'numbers','approve_request'} and body['approve_request'] is True,'consent-required')
                    result=self._bundle.history_request(body['numbers'],True)
                elif op=='bundle-history-prove':
                    require(set(body)=={'request','approve_linking'} and body['approve_linking'] is True,'consent-required')
                    result=self._bundle.history_prove(body['request'],True)
                elif op=='bundle-history-verify':
                    require(set(body)=={'response','request_sha256'},'message-schema')
                    result=self._bundle.history_verify(body['response'],body['request_sha256'])
                elif op=='bundle-history-requests':
                    require(set(body)=={'after','limit'},'message-schema')
                    result=self._bundle.history_requests(body['after'],body['limit'])
                elif op=='bundle-address-request':
                    require(set(body)=={'post_id','address','approve_address_disclosure'} and body['approve_address_disclosure'] is True,'consent-required')
                    result=self._bundle.request_address(body['post_id'],body['address'],True)
                elif op=='bundle-address-result':
                    require(set(body)=={'post_id','submission_id','request_sha256','signature'},'message-schema')
                    result=self._bundle.accept_address(body['post_id'],body['submission_id'],body['request_sha256'],body['signature'])
                elif op=='bundle-publish':
                    require(not self._legacy_readonly,'legacy-publication-disabled')
                    require(set(body)=={'post','selection','approve_publication'} and body['approve_publication'] is True,'consent-required')
                    result=self._bundle.publish(body['post'],body['selection'],True)
                elif op=='bundle-renew':
                    require(not self._legacy_readonly,'legacy-publication-disabled')
                    require(set(body)=={'post_id','expected_submission_id','approve_fresh_proof'} and body['approve_fresh_proof'] is True,'consent-required')
                    result=self._bundle.renew(body['post_id'],body['expected_submission_id'],True)
                elif op=='bundle-recover':
                    require(set(body)=={'post_id'},'message-schema')
                    result=(self._bundle.recover_read_only(body['post_id']) if self._legacy_readonly
                        else self._bundle.recover(body['post_id']))
                elif op=='bundle-check-existing':
                    require(set(body)=={'post_id'},'message-schema')
                    result=self._bundle.recover_read_only(body['post_id'])
                elif op in ('bundle-outbox','bundle-threads'):
                    require(set(body)=={'after','limit'},'message-schema')
                    result=getattr(self._bundle,'outbox' if op=='bundle-outbox' else 'threads')(body['after'],body['limit'])
                elif op=='bundle-thread':
                    require(set(body)=={'thread_id','after','limit'},'message-schema')
                    result=self._bundle.thread(body['thread_id'],body['after'],body['limit'])
                elif op=='bundle-numbers':
                    require(set(body)=={'numbers'},'message-schema');result=self._bundle.numbers(body['numbers'])
                elif op=='bundle-clear-cache':
                    require(set(body)=={'confirm_cache_clear'} and body['confirm_cache_clear'] is True,'consent-required')
                    result=self._bundle.clear_cache()
                elif op=='bundle-export-public':
                    require(set(body)=={'post_number','approve_public_export'},'native-message')
                    result=self._bundle.archive_export(body['post_number'],body['approve_public_export'])
                elif op=='bundle-import-public':
                    require(set(body)=={'scope','record','confirm_public_archive_import'},'native-message')
                    result=self._bundle.archive_import(body['scope'],body['record'],body['confirm_public_archive_import'])
                else:raise Rejected('message-schema')
            elif op.startswith('count-'):
                require(self._counts is not None,'count-wallet-unavailable');action=op[6:]
                if action in ('status','recover','cancel'):
                    require(not body,'message-schema')
                    result=self._counts.local_status() if action=='status' else getattr(self._counts,action)()
                elif action=='begin':
                    require(not self._legacy_readonly,'legacy-publication-disabled')
                    require(set(body)=={'username','approve_public_profile_lookup'} and body['approve_public_profile_lookup'] is True,'consent-required')
                    result=self._counts.begin(body['username'],True)
                elif action=='check-post':
                    require(set(body)=={'post','approve_source_check'} and body['approve_source_check'] is True,'consent-required')
                    result=self._counts.check_post(body['post'],True)
                elif action=='poll-registration':
                    require(set(body)=={'approve_source_check'} and body['approve_source_check'] is True,'consent-required')
                    result=self._counts.poll_registration(True)
                elif action=='forget':
                    require(set(body)=={'confirm_local_deletion'} and body['confirm_local_deletion'] is True,'consent-required')
                    result=self._counts.forget()
                else:raise Rejected('message-schema')  # no browser-supplied general count challenge
            elif op=='base-capabilities':
                require(not body,'message-schema')
                result=(self._base.capabilities() if self._base is not None else {'configured':False,'experimental':True})
            elif op.startswith('base-'):
                require(self._base is not None,'base-service-unavailable')
                if op=='base-outbox':
                    require(set(body)=={'after','limit'},'message-schema');result=self._base.outbox(body['after'],body['limit'])
                elif op=='base-publish':
                    require(not self._legacy_readonly,'legacy-publication-disabled')
                    require(set(body)=={'post','facts','approve_publication'} and body['approve_publication'] is True,
                        'consent-required')
                    result=self._base.publish(body['post'],body['facts'],True)
                elif op=='base-recover':
                    require(set(body)=={'post_id'},'message-schema')
                    result=(self._base.recover_read_only(body['post_id']) if self._legacy_readonly
                        else self._base.recover(body['post_id']))
                elif op=='base-check-existing':
                    require(set(body)=={'post_id'},'message-schema')
                    result=self._base.recover_read_only(body['post_id'])
                elif op=='base-discussion':
                    require(set(body)=={'after','limit'},'message-schema');result=self._base.discussion(body['after'],body['limit'])
                else:raise Rejected('message-schema')
            elif op=='post-capabilities':
                require(not body,'message-schema')
                result={'configured':self._posts is not None,'profile':POST_REFERENCE,'identity_disclosed':False,
                        'laboratory':True,'verified':False}
            elif op.startswith('post-'):
                require(self._posts is not None,'post-verifier-unavailable')
                if op in ('post-status','post-available','post-recover'):
                    require(not body,'message-schema');result=getattr(self._posts,op[5:])()
                elif op in ('post-use','post-retry'):
                    require(self._public is None,'legacy-publication-disabled')
                    require(set(body)=={'post','facts','approve_facts','approve_identity_disclosure'},'message-schema')
                    require(type(body['facts']) is list and body['approve_facts']==body['facts']
                            and type(body['approve_identity_disclosure']) is bool and body['approve_identity_disclosure'] is False,
                            'consent-required')
                    result=getattr(self._posts,op[5:])(body['post'],body['facts'],body['approve_facts'],body['approve_identity_disclosure'])
                elif op=='post-inspect':
                    require(set(body)=={'post','facts','nonce'},'message-schema')
                    result=self._posts.inspect(body['post'],body['facts'],body['nonce'])
                elif op=='post-complete':
                    require(set(body)=={'post','facts','nonce','confirm_published'},'message-schema')
                    require(body['confirm_published'] is True,'consent-required')
                    result=self._posts.complete(body['post'],body['facts'],body['nonce'],body['confirm_published'])
                elif op=='post-discard':
                    require(set(body)=={'confirm_local_discard'} and body['confirm_local_discard'] is True,'message-schema')
                    result=self._posts.discard(True)
                else:raise Rejected('message-schema')
            elif op in ('status','recover','cancel'):
                require(not body,'message-schema')
                result=(self._bridge.local_status() if op=='status' else getattr(self._bridge,op)())
            elif op=='begin':
                require(self._public is None,'legacy-publication-disabled')
                require(set(body)=={'username','approve_public_profile_lookup'},'message-schema')
                require(body['approve_public_profile_lookup'] is True,'consent-required')
                result=self._bridge.begin(body['username'],True)
            elif op=='check-post':
                require(set(body)=={'post','approve_source_check'},'message-schema')
                require(body['approve_source_check'] is True,'consent-required')
                result=self._bridge.check_post(body['post'],True)
            elif op=='poll-registration':
                require(set(body)=={'approve_source_check'} and body['approve_source_check'] is True,'consent-required')
                result=self._bridge.poll_registration(True)
            elif op=='forget':
                require(set(body)=={'confirm_local_deletion'} and body['confirm_local_deletion'] is True,'consent-required')
                result=self._bridge.forget()
            elif op=='present':
                require(set(body)=={'challenge','approve_facts','approve_identity_disclosure'},'message-schema')
                challenge=body['challenge']
                require(type(challenge) is dict and set(challenge)=={'profile','nonce','scope','facts','identity',
                    'registry_sequence','created_at','expires_at'} and challenge['profile']==CREDENTIAL,'message-schema')
                hex_string(challenge['nonce'],64);hex_string(challenge['scope'],64)
                timestamp(challenge['created_at']);timestamp(challenge['expires_at'])
                require(0<challenge['expires_at']-challenge['created_at']<=60
                        and type(challenge['registry_sequence']) is int and challenge['registry_sequence']>=0
                        and type(challenge['identity']) is bool and type(challenge['facts']) is list
                        and 1<=len(challenge['facts'])<=2 and all(type(f) is str for f in challenge['facts'])
                        and len(set(challenge['facts']))==len(challenge['facts'])
                        and set(challenge['facts'])<={'account-controlled','followers-at-least-10000'},'message-schema')
                require(body['approve_facts']==challenge['facts'] and type(body['approve_identity_disclosure']) is bool
                        and body['approve_identity_disclosure']==challenge['identity'],'consent-required')
                result={'proof':self._bridge.present(challenge)}
            else:raise Rejected('message-schema')
            require(type(result) is dict,'native-result')
            return {'profile':PROFILE,'id':ident,'status':'ok','result':result,'laboratory':True,'verified':False}
        except Exception as error:
            code='native-operation-unavailable'
            # Fixed public recovery conditions only. Never serialize exception
            # text, arbitrary arguments, SDK details, records or private paths.
            if op=='public-publish' and isinstance(error,Rejected) and len(error.args)==1 and type(error.args[0]) is str:
                code={'follower-publication-window-too-short':'publication-follower-window-unavailable',
                      'ticket-wallet-empty':'publication-ticket-needed'}.get(error.args[0],code)
            return {'profile':PROFILE,'id':ident,'status':'rejected','code':code,
                    'recoverable':True,'laboratory':True,'verified':False}


def receive(stream):
    header=stream.read(4)
    if not header:return None
    require(len(header)==4,'native-frame')
    size=struct.unpack('=I',header)[0];require(0<size<=MAX_MESSAGE,'native-frame');data=bytearray()
    while len(data)<size:
        chunk=stream.read(size-len(data));require(bool(chunk),'native-frame');data.extend(chunk)
    return strict_json(bytes(data),max_bytes=MAX_MESSAGE)


def send(stream,result):
    data=canonical(result);require(len(data)<=MAX_MESSAGE,'native-frame')
    stream.write(struct.pack('=I',len(data))+data);stream.flush()


def serve(source,target,app):
    for _ in range(MAX_MESSAGES):
        message=receive(source)
        if message is None:return
        send(target,app.dispatch(message))


def main():
    try:
        config=configuration();authorize(sys.argv[1:],config['browser'])
        if config['profile'] in ('nockapp-installed-public-native-v6','nockapp-installed-public-native-v7','nockapp-installed-public-direct-v1','nockapp-installed-public-renewal-v1'):
            from public_installation import factory as public_factory
            app=NativeApplication(None,public_app=public_factory(config,ROOT))
            serve(sys.stdin.buffer,sys.stdout.buffer,app);return 0
        base=bundle=counts=None
        if 'bundle_approval' in config:
            from bundle_desktop import BundleDesktop
            from base_enrollment import BaseEnrollment
            bundle=BundleDesktop(config['bundle_directory'],config['bundle_approval'],config['bundle_chain'],config['wallet_directory'],
                count_directory=config.get('count_wallet_directory'),count_approval=config.get('count_approval'))
            bridge=LazyBridge(lambda:BaseEnrollment(config['wallet_directory'],bundle))
            if 'count_approval' in config:
                from count_enrollment import CountEnrollment
                counts=LazyBridge(lambda:CountEnrollment(config['count_wallet_directory'],bundle,config['count_approval']))
        elif 'base_approval' in config:
            from base_desktop import BaseDesktop
            from base_enrollment import BaseEnrollment
            base=BaseDesktop(config['base_directory'],config['base_approval'],config['base_chain'],config['wallet_directory'])
            bridge=BaseEnrollment(config['wallet_directory'],base)
        else:
            bridge=(DomainBridge(config['wallet_directory'],config['issuer_approval'],endpoint=config['issuer_endpoint'])
                    if 'issuer_endpoint' in config else
                    DomainBridge(config['wallet_directory'],config['issuer_approval'],config['issuer_port']))
        posts=PostHolder(bridge,config['verifier_approval']) if 'verifier_approval' in config else None
        serve(sys.stdin.buffer,sys.stdout.buffer,NativeApplication(bridge,posts,base,bundle=bundle,counts=counts));return 0
    except Exception:return 1  # No private inputs/config/path/exception diagnostics.


if __name__=='__main__':raise SystemExit(main())
