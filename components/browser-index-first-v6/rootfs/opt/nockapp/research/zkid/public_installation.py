"""Installer-owned public mode configuration and concrete native factory.

No keys/credentials or caller-chosen paths/endpoints in browser operations.
Network clients are constructed without connecting; reads need no keyring.
Actual deployment bindings must be supplied and reviewed before installation.
"""
import copy
import hashlib
from pathlib import Path
import re
import ssl

from authorship import AuthorshipNative
from authorship_desktop_v5 import AuthorshipDesktopV5
from base_rpc import BaseRPC
from policy import canonical,require
from permissionless_index import PublicIndexReader,digest
from bundle_disk_cache import LazyCheckpointStore
from public_content_v5 import PublicContent
from public_content_cache_v5 import LazyContentCacheV5
from public_verified_cache import LazyVerifiedResultCache
from public_desktop_v5 import PublicDesktopV5
from public_issuer_views import PublicIssuerViews
from public_reader_v6 import HistoricalPublicReader
from public_s3_v5 import S3PublicOrigin
from renewal_native_v3 import RenewalNative
from ticket_native_v1 import TicketNative
from ticket_offer_v1 import TicketOffer,manifest_hash,OFFER_V2,hex_value,configured_offer
from ticket_wallet_v1 import TicketWallet
from ticket_routed_transport_v1 import ticket_endpoint as endpoint, ticket_remote, refund_remote, distinct_identities
from ticket_public_client_v2 import TicketPublicOrigin,TicketPublicRelay
from ticket_publisher_v2 import TicketPublisher

PROFILE='nockapp-installed-public-native-v6'
PROFILE_V7='nockapp-installed-public-native-v7'
PROFILE_DIRECT='nockapp-installed-public-direct-v1'
BINARIES={'author':'local/authorship-native/debug/nockapp-authorship-v4',
    'abi':'local/base-tools/cast',
    'renewal':'local/renewal-native/debug/nockapp-renewal-count-v3',
    'ticket':'local/ticket-tools/nockapp-ticket-worker-v1',
    'count':'local/count-native/debug/nockapp-zkid-count-v2',
    'domain':'domain-crypto/target/debug/nockapp-zkid-domain-research'}


def source_files(root):
    """Complete local static Python import closure, including lazy imports."""
    from source_module_closure import module_closure
    seen=module_closure(root,['domain_native.py','domain_native_entrypoint.py','public_installation.py','public_native_v6.py'])
    seen.update('external/'+name for name in ('x_keystore.py','x_holder.py','x_policy.py'))
    return seen


def source_path(root,name):
    if name in ('external/x_keystore.py','external/x_holder.py','external/x_policy.py'):
        return Path(root).parent/'nock-mpc/source-auth'/Path(name).name
    return Path(root)/name


def _path(value):
    p=Path(value)
    require(type(value) is str and p.is_absolute() and '..' not in p.parts
        and not any(v.startswith('.env') for v in p.parts)
        and not any(v.is_symlink() for v in (p,*p.parents)),'public-install-path')
    return p


def validate(value):
    if type(value) is dict and value.get('profile')in ('nockapp-installed-public-batch-v1','nockapp-installed-public-index-first-v1'):
        from batch_checkout_v2.installation import validate as batch_validate
        return batch_validate(value)
    if type(value) is dict and value.get('profile')=='nockapp-installed-public-renewal-v1':
        from public_renewal_installation_v1 import validate as renewal_validate
        return renewal_validate(value)
    if type(value) is dict and value.get('profile')==PROFILE_V7:
        from ticket_refund_vault_v1 import scope_manifest
        from ticket_routed_transport_v1 import refund_endpoint
        fields={'refund_endpoint','refund_vault','refund_vault_sha256'}
        require(fields<=set(value),'public-install-refund-config')
        base={k:v for k,v in value.items() if k not in fields};base['profile']=PROFILE
        validate(base)
        scope_manifest(value['refund_vault'],value['offer'],value['offer_sha256'],value['refund_vault_sha256'])
        a=refund_endpoint(value['refund_endpoint'])
        require(a['offer_sha256']==value['offer_sha256'] and a['policy_sha256']==value['refund_vault_sha256'],'public-install-refund-endpoint')
        distinct_identities([value['payment_endpoint'],value['publication_endpoint'],a])
        return copy.deepcopy(value)
    direct=type(value) is dict and value.get('profile')==PROFILE_DIRECT
    fields={'profile','browser','data_directory','chain','issuer','storage','binary_sha256','files_sha256','legacy_wallets'}
    if not direct:fields|={'offer','offer_sha256','payment_endpoint','publication_endpoint','operator_ca_pem'}
    require(type(value) is dict and set(value)==fields
        and value['profile'] in (PROFILE,PROFILE_DIRECT),'public-install-config')
    _path(value['data_directory'])
    browser=value['browser']
    require(type(browser) is dict and set(browser)=={'kind','origin'} and browser['kind']=='chrome'
        and type(browser['origin']) is str and re.fullmatch(r'chrome-extension://[a-p]{32}/',browser['origin']),'public-install-browser')
    c=value['chain'];require(type(c) is dict and set(c)=={'chain_id','application','contract','runtime_keccak','rpc_endpoint'}
        and type(c['chain_id']) is int and c['chain_id']==84532,'public-install-chain')
    digest(c['application']);digest(c['runtime_keccak']);hex_value(c['contract'],20)
    # Reuse the strict public HTTPS URL validation; construction performs no I/O.
    BaseRPC(c['rpc_endpoint'],rate=32,burst=64)
    i=value['issuer'];require(type(i) is dict and set(i)==({'definition_hash'} if direct else
        {'contract','runtime_keccak','updater','definition_hash','deployment_block'}),'public-install-issuer')
    digest('0x'+i['definition_hash'])
    if not direct:
        hex_value(i['contract'],20);hex_value(i['updater'],20);digest(i['runtime_keccak'])
        require(type(i['deployment_block']) is int and 0<=i['deployment_block']<2**53,'public-install-issuer')
    s=value['storage'];require(type(s) is dict and set(s)=={'region','bucket','account_id'},'public-install-storage')
    from public_s3_endpoints import s3_host
    s3_host(s['region'],s['bucket']);require(type(s['account_id']) is str and re.fullmatch(r'[0-9]{12}',s['account_id']),'public-install-storage')
    if not direct:
        require(manifest_hash(value['offer'])==value['offer_sha256'] and value['offer']['terms']['profile']==OFFER_V2,'public-install-offer')
        t=value['offer']['terms']
        require(t['chain_id']==c['chain_id'] and t['application']==c['application'] and t['index_contract']==c['contract']
            and t['index_runtime_keccak']==c['runtime_keccak'],'public-install-offer-context')
        for key,service in (('payment_endpoint','payment'),('publication_endpoint','publication')):
            a=endpoint(value[key]);require(a['service']==service and a['offer_sha256']==value['offer_sha256'],'public-install-endpoint')
        distinct_identities([value['payment_endpoint'],value['publication_endpoint']])
        ca=value['operator_ca_pem'];require(type(ca) is str and 0<len(ca.encode())<=32768,'public-install-ca')
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        try:ctx.load_verify_locations(cadata=ca)
        except Exception:require(False,'public-install-ca')
    pins=value['binary_sha256'];require(type(pins) is dict and set(pins)==set(BINARIES),'public-install-binaries')
    for pin in pins.values():digest('0x'+pin)
    require(type(value['files_sha256']) is dict and value['files_sha256'],'public-install-files')
    for name,h in value['files_sha256'].items():
        require(type(name) is str and not Path(name).is_absolute() and '..' not in Path(name).parts
            and not any(p.startswith('.env') for p in Path(name).parts) and name.endswith('.py'),'public-install-files')
        digest('0x'+h)
    legacy=value['legacy_wallets'];require(type(legacy) is list and len(legacy)<=8,'public-install-legacy')
    paths=[_path(value['data_directory'])]
    for row in legacy:
        require(type(row) is dict and row.get('kind') in ('author-v4','count-v2','domain-v1')
            and set(row)==({'kind','directory','binding'} if row['kind']=='author-v4' else {'kind','directory'}),'public-install-legacy')
        p=_path(row['directory']);require(all(not p.is_relative_to(old) and not old.is_relative_to(p) for old in paths),'public-install-overlap');paths.append(p)
        if row['kind']=='author-v4':
            from authorship_desktop import binding
            old=binding(row['binding']);require(old['issuer_definition']==i['definition_hash'],'public-install-legacy')
    return copy.deepcopy(value)


def factory(config,root):
    if type(config) is dict and config.get('profile')=='nockapp-installed-public-renewal-v1':
        from public_renewal_installation_v1 import factory as renewal_factory
        return renewal_factory(config,root)
    v=validate(config);root=_path(str(root))
    direct=v['profile']==PROFILE_DIRECT
    batch=v['profile']in ('nockapp-installed-public-batch-v1','nockapp-installed-public-index-first-v1')
    indexed=v['profile']=='nockapp-installed-public-index-first-v1'
    if batch:
        for row in v['legacy_ticket_scopes']:
            require(_path(row['directory']).is_dir(),'batch-install-legacy-missing')
    require(set(v['files_sha256'])==source_files(root),'public-install-source-closure')
    for name,h in v['files_sha256'].items():
        p=source_path(root,name);_path(str(p));require(hashlib.sha256(p.read_bytes()).hexdigest()==h,'public-install-code-changed')
    binaries={name:root/path for name,path in BINARIES.items()}
    for name,p in binaries.items():
        _path(str(p));require(hashlib.sha256(p.read_bytes()).hexdigest()==v['binary_sha256'][name],'public-install-binary-changed')
    author_native=AuthorshipNative(binaries['author']);renewal_native=RenewalNative(binaries['renewal'])
    if not direct:
        ticket_native=TicketNative(binaries['ticket'],v['binary_sha256']['ticket'])
        offer=configured_offer(v['offer'],v['offer_sha256'],ticket_native)
    c=v['chain'];i=v['issuer'];data=_path(v['data_directory'])
    require(not data.is_relative_to(root) and not root.is_relative_to(data),'public-install-data-code-overlap')
    rpc=BaseRPC(c['rpc_endpoint'],rate=32,burst=64)
    rpc.public_read_batching=callable(getattr(rpc,'read_many',None))
    index=PublicIndexReader(rpc,c['contract'],c['application'],runtime_hash=c['runtime_keccak'],
        checkpoint_store=LazyCheckpointStore(data/'index-checkpoints'))
    views=None if direct else PublicIssuerViews(rpc,i['contract'],i['runtime_keccak'],i['updater'],i['definition_hash'],i['deployment_block'],index_contract=c['contract'])
    previous=[];legacy_sources=[]
    for old in v['legacy_wallets']:
        if not Path(old['directory']).exists():continue
        if old['kind']=='author-v4':
            from authorship_desktop import AuthorshipDesktop
            previous.append(AuthorshipDesktop(old['directory'],old['binding'],author_native))
        elif old['kind']=='count-v2':
            from count_desktop import CountDesktop
            from count_pipeline import CountNative
            legacy_sources.append(CountDesktop(old['directory'],i['definition_hash'],CountNative(binaries['count'])))
        else:
            from domain_desktop import DomainDesktop
            from domain_pipeline import Native
            legacy_sources.append(DomainDesktop(old['directory'],Native(binaries['domain'])))
    # Create only a NEW app root privately. Existing directories keep their
    # permissions; an unsafe existing parent disables the optional cache rather
    # than silently chmodding owner/legacy state during a read.
    try:data.mkdir(mode=0o700,parents=True,exist_ok=False)
    except FileExistsError:pass
    author=AuthorshipDesktopV5(data/'author-v5',{'protocol':5,'chain_id':84532,'application':c['application'],
        'contract':c['contract'],'issuer_definition':i['definition_hash']},author_native,
        previous_authors=previous,legacy_sources=legacy_sources)
    public_tls=ssl.create_default_context();public_tls.minimum_version=ssl.TLSVersion.TLSv1_2
    public=S3PublicOrigin(**v['storage'],context=public_tls)
    if not direct:
        tickets=TicketWallet(data/'ticket-scopes'/offer.hash if batch and offer.terms['profile']=='nockapp-public-prepaid-batch-offer-v3'else data/'tickets-v2',offer)
        operator=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);operator.minimum_version=ssl.TLSVersion.TLSv1_3
        operator.load_verify_locations(cadata=v['operator_ca_pem'])
        payment=ticket_remote(v['payment_endpoint'],operator);publication=ticket_remote(v['publication_endpoint'],operator)
    if batch:
        from batch_checkout_v2.scopes import TicketScopes,ScopedOrigin,ScopedRelay
        old=[];apps=[]
        for row in v['legacy_ticket_scopes']:
            require(_path(row['directory']).is_dir(),'batch-install-legacy-missing')
            old_offer=configured_offer(row['offer'],row['offer_sha256'],ticket_native)
            wallet=TicketWallet(row['directory'],old_offer)
            remote=ticket_remote(row['publication_endpoint'],operator)
            old.append((wallet,remote));apps.append((wallet,ticket_remote(row['payment_endpoint'],operator),row))
        scopes=TicketScopes((tickets,publication),old,rpc=index.rpc)
        if indexed:
            from ticket_transport_v3 import IndexedOrigin,IndexedRelay
            origin=IndexedOrigin(public,publication)
        else:origin=ScopedOrigin(public,scopes,lambda:desktop.clock())
    else:origin=public if direct else TicketPublicOrigin(public,publication,tickets)
    content=PublicContent(origin,disk_cache=LazyContentCacheV5(data/'public-bundles-v5'))
    reader=HistoricalPublicReader(index,content,author_native,renewal_native=renewal_native,issuer_views=views,
        issuer_authority=hashlib.sha256(canonical({'mode':'direct-without-issuer-views','issuer':i} if direct else i)).hexdigest(),
        result_disk_cache=LazyVerifiedResultCache(data/'verified-results-v1'))
    relay=IndexedRelay(scopes,index,lambda:desktop.clock())if indexed else ScopedRelay(scopes,index,lambda:desktop.clock())if batch else None if direct else TicketPublicRelay(TicketPublisher(tickets,publication.submit),index)
    desktop_type=PublicDesktopV5
    if indexed:
        from public_desktop_v6 import IndexFirstDesktop
        desktop_type=IndexFirstDesktop
    desktop=desktop_type(data/'outbox-v5',author,index,content,reader,relay=relay)
    if batch:
        from batch_checkout_v2.installation import assemble_apps
        return assemble_apps(desktop,scopes,[*apps,(tickets,payment,v)],operator,v['checkout_scope'])
    if direct:
        from public_native_direct import PublicDirectApplication
        return PublicDirectApplication(desktop)
    if v['profile']==PROFILE_V7:
        from public_native_v7 import PublicApplicationV7
        return PublicApplicationV7(desktop,tickets,payment,refund_remote(v['refund_endpoint'],operator),
            v['refund_vault'],v['refund_vault_sha256'])
    from public_native_v6 import PublicApplicationV6
    return PublicApplicationV6(desktop,tickets,payment)
