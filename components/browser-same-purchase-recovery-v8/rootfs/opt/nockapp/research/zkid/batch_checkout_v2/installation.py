"""Explicit batch installation profile; old state stays in its original scope.

Common identity/index/storage checks are reused without constructing a pretend
old offer or rewriting encrypted records. Checkout selection is installer-pinned,
so a lost response cannot silently switch a browser onto a different purchase.
"""
import copy,ssl
from pathlib import Path
from policy import require
from ticket_offer_v1 import configured_manifest_hash,configured_offer
from ticket_routed_transport_v1 import ticket_endpoint,refund_endpoint,distinct_identities,refund_remote
from ticket_refund_vault_v1 import scope_manifest
from public_native_v7 import PublicApplicationV7
from .offer import PROFILE as OFFER

PROFILE='nockapp-installed-public-batch-v1'
PROFILE_INDEX='nockapp-installed-public-index-first-v1'
TICKET_FIELDS={'offer','offer_sha256','payment_endpoint','publication_endpoint',
    'refund_endpoint','refund_vault','refund_vault_sha256'}


def validate(value):
    from public_installation import validate as common_validate,PROFILE_DIRECT,_path
    common={'profile','browser','data_directory','chain','issuer','storage','binary_sha256',
        'files_sha256','legacy_wallets','operator_ca_pem','legacy_ticket_scopes','checkout_scope'}
    require(type(value) is dict and set(value)==common|TICKET_FIELDS
        and value['profile'] in (PROFILE,PROFILE_INDEX),'batch-install-schema')
    base={k:v for k,v in value.items()if k not in TICKET_FIELDS|{
        'operator_ca_pem','legacy_ticket_scopes','checkout_scope'}}
    base['profile']=PROFILE_DIRECT
    issuer=value['issuer']
    require(type(issuer) is dict and set(issuer)=={'contract','runtime_keccak','updater','definition_hash','deployment_block'},'batch-install-issuer')
    from ticket_offer_v1 import hex_value
    hex_value(issuer['contract'],20);hex_value(issuer['updater'],20);hex_value(issuer['runtime_keccak'],32)
    require(type(issuer['deployment_block']) is int and 0<=issuer['deployment_block']<2**53,'batch-install-issuer')
    base['issuer']={'definition_hash':issuer['definition_hash']};common_validate(base)
    ca=value['operator_ca_pem'];require(type(ca) is str and 0<len(ca.encode())<=32768,'batch-install-ca')
    try:ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=ca)
    except Exception:require(False,'batch-install-ca')
    from ticket_offer_v1 import OFFER_V2
    require(value['offer']['terms'].get('profile')in ((OFFER,)if value['profile']==PROFILE else(OFFER,OFFER_V2)),'batch-install-offer')
    primary=(_path(value['data_directory'])/'ticket-scopes'/value['offer_sha256']if value['offer']['terms']['profile']==OFFER
        else _path(value['data_directory'])/'tickets-v2')
    legacy=value['legacy_ticket_scopes'];require(type(legacy) is list and len(legacy)<=4,'batch-install-legacy')
    require(len(legacy)+len(value['legacy_wallets'])<=8,'batch-install-mount-limit')
    paths=[primary];hashes=[]
    for row in [value,*legacy]:
        if row is not value:
            require(type(row) is dict and set(row)==TICKET_FIELDS|{'directory'},'batch-install-legacy')
            path=_path(row['directory'])
            protected=[_path(v['directory'])for v in value['legacy_wallets']]
            protected.extend(_path(value['data_directory'])/n for n in ('author-v5','renewal-v3','outbox-v5'))
            require(path!=_path(value['data_directory']) and not _path(value['data_directory']).is_relative_to(path)
                and all(not path.is_relative_to(p) and not p.is_relative_to(path)for p in [*paths,*protected]),'batch-install-overlap');paths.append(path)
        require(configured_manifest_hash(row['offer'])==row['offer_sha256'],'batch-install-offer-pin')
        hashes.append(row['offer_sha256']);t=row['offer']['terms'];c=value['chain']
        require(all(t[k]==c[v]for k,v in (('chain_id','chain_id'),('application','application'),
            ('index_contract','contract'),('index_runtime_keccak','runtime_keccak'))),'batch-install-context')
        endpoints=[]
        for key,service in (('payment_endpoint','payment'),('publication_endpoint','publication')):
            endpoint=ticket_endpoint(row[key]);require(endpoint['service']==service
                and endpoint['offer_sha256']==row['offer_sha256'],'batch-install-endpoint');endpoints.append(endpoint)
        if value['profile']==PROFILE_INDEX:
            require(row['publication_endpoint']['profile']=='nockapp-index-first-publication-endpoint-v1','index-first-install-channel')
        endpoint=refund_endpoint(row['refund_endpoint'])
        require(endpoint['offer_sha256']==row['offer_sha256']
            and endpoint['policy_sha256']==row['refund_vault_sha256'],'batch-install-refund-endpoint')
        scope_manifest(row['refund_vault'],row['offer'],row['offer_sha256'],row['refund_vault_sha256'])
        distinct_identities([*endpoints,endpoint])
    require(len(set(hashes))==len(hashes) and value['checkout_scope']in hashes,'batch-install-checkout')
    return copy.deepcopy(value)


class BatchApplication:
    def __init__(self,desktop,scopes,apps,checkout):
        self.desktop,self.scopes,self.apps=desktop,scopes,apps
        self.selected=apps[checkout];self.tickets=self.selected.tickets;self.payment=self.selected.payment

    def dispatch(self,operation,body):
        if operation=='public-capabilities':
            return {**self.selected.dispatch(operation,body),'ticket_page_snapshot':True,'same_purchase_resume':True}
        if operation=='public-ticket-page':
            require(type(body)is dict and not body,'batch-recovery-schema')
            caps=self.dispatch('public-capabilities',{})
            return {'profile':'nockapp-ticket-page-v1','capabilities':caps,
                'offer':self.selected.dispatch('public-ticket-offer',{}),
                'bulk':self.selected.dispatch('public-ticket-bulk-status',{}),
                'pending':self.selected.dispatch('public-ticket-pending',{}),
                'refund':self.selected.dispatch('public-ticket-refund-state',{})if caps.get('refund_payout_configured')else None,
                'inventory':self.dispatch('public-ticket-status',{}),
                'earlier':self.dispatch('public-ticket-earlier-status',{})}
        if operation=='public-ticket-earlier-status':
            require(type(body)is dict and not body,'batch-recovery-schema')
            rows=[]
            for parameters,app in self.apps.items():
                if app.tickets is self.scopes.primary[0]:continue
                saved=app.dispatch('public-ticket-bulk-status',{})
                if saved['phase']in ('none','complete'):continue
                rows.append({'parameters':parameters,'offer':app.dispatch('public-ticket-offer',{}),'purchase':saved})
            return {'profile':'nockapp-earlier-ticket-purchases-v1','purchases':rows}
        if operation=='public-ticket-earlier-recovery':
            require(type(body)is dict and set(body)=={'parameters','operation','body'}
                and type(body['parameters'])is str and body['parameters']in self.apps
                and type(body['operation'])is str and type(body['body'])is dict,'batch-recovery-schema')
            app=self.apps[body['parameters']]
            require(app.tickets is not self.scopes.primary[0]
                and body['operation']in ('public-ticket-bulk-status','public-ticket-bulk-progress',
                    'public-ticket-bulk-recover','public-ticket-bulk-resume','public-ticket-bulk-record-payment',
                    'public-ticket-bulk-self-review','public-ticket-bulk-self-arm'),'batch-recovery-only')
            if body['operation']in ('public-ticket-bulk-self-review','public-ticket-bulk-self-arm'):
                counts=self.scopes.status();saved=app.dispatch('public-ticket-bulk-status',{})
                require(saved['phase']!='none'and counts['available']+counts['reserved']+50-saved['settled_tickets']<=64,'ticket-wallet-full')
            # The original controller validates the saved batch, exact payment,
            # finality and import cursor. No prepare/arm/send/reset is exposed.
            return app.dispatch(body['operation'],body['body'])
        if operation=='public-ticket-status':
            result=self.selected.dispatch(operation,body)
            # Counts and initialization describe the SAME set of wallets. The
            # primary can be empty while retained legacy tickets still exist.
            status=self.scopes.status(include_initialization=True,now=int(self.desktop.clock()))
            clear=status.pop('legacy_purchase_clear')
            count=50 if self.tickets.offer.terms.get('profile')=='nockapp-public-prepaid-batch-offer-v3'else 2
            capacity=status['available']+status['reserved']+count<=64
            return {**result,**status,'can_purchase':result['can_purchase']and clear and capacity}
        from .offer import BatchOffer
        if (isinstance(self.tickets.offer,BatchOffer) and self.tickets is self.scopes.primary[0] and operation in
                ('public-ticket-prepare','public-ticket-arm','public-ticket-close-attempt')):
            require(False,'batch-checkout-use-fifty-ticket-flow')
        if self.tickets is not self.scopes.primary[0]and operation in ('public-ticket-prepare','public-ticket-arm','public-ticket-bulk-prepare','public-ticket-bulk-arm'):
            require(False,'ticket-legacy-recovery-only')
        if operation in ('public-ticket-prepare','public-ticket-arm'):
            with self.scopes.purchase_guard(2):return self.selected.dispatch(operation,body)
        return self.selected.dispatch(operation,body)


def assemble_apps(desktop,scopes,rows,context,checkout):
    apps={}
    for wallet,payment,row in rows:
        apps[wallet.offer.hash]=PublicApplicationV7(desktop,wallet,payment,
            refund_remote(row['refund_endpoint'],context),row['refund_vault'],row['refund_vault_sha256'])
    scopes.primary[0].purchase_scopes=scopes
    return BatchApplication(desktop,scopes,apps,checkout)
