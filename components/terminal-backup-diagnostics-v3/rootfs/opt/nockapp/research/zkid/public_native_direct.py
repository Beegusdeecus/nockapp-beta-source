"""Installed direct-payer route: no ticket services or invented issuer views.

The owner uploads only an explicitly exported public bundle. Before a wallet
request, check the pinned log and fetch those exact bytes anonymously from the
configured origin. This check establishes current availability, not retention.
"""
from policy import require
from public_native_v6 import PublicApplicationV6
from public_native_v5 import PublicApplicationV5
from public_bundle_v5 import encode,decode,MAX_BYTES
from base_protocol import sha
from permissionless_index import submission_data,digest


class PublicDirectApplication(PublicApplicationV6):
    def __init__(self,desktop):
        require(desktop.relay is None and desktop.reader.issuer_views is None,'direct-components')
        super().__init__(desktop,None,None)

    def dispatch(self,operation,body):
        require(type(operation) is str and type(body) is dict,'direct-native-schema')
        if operation=='public-capabilities':
            base=PublicApplicationV5.dispatch(self,operation,body)
            return {**base,'verifier_release':8,'publication_mode':'direct',
                'anonymous_ticket_packs':False,'source_enrollment_configured':False,
                'historical_issuer_views':False}
        require(not operation.startswith('public-ticket-') and operation!='public-publish',
            'direct-use-export-and-wallet')
        if operation=='public-direct-public-ready':
            require(set(body)=={'bundle_hash','approve_publication','approve_public_payer'}
                and body['approve_publication'] is True and body['approve_public_payer'] is True,'consent-required')
            h=digest(body['bundle_hash']);d=self.desktop
            # A fee payer needs public evidence only: no outbox, holder key,
            # identity adoption or claim that the payer authored this bundle.
            raw=d.content.origin.get(h,MAX_BYTES)
            bundle=decode(raw,h)
            d._validate_for_submission({'bundle':bundle})
            require(d.index.number_for_hash(h) is None,'direct-already-indexed-check-public-log')
            return {'scope':dict(d.scope),'bundle_hash':h,'calldata':submission_data(h),
                'public_readback_checked':True,'payer_address_public':True}
        if operation=='public-direct-ready':
            require(set(body)=={'post_id','approve_publication','approve_public_payer'}
                and body['approve_publication'] is True and body['approve_public_payer'] is True,'consent-required')
            d=self.desktop
            with d.lock():
                row=d._row(d._outbox(),body['post_id'])
                require(row['bundle'] is not None,'v5-bundle-unsaved')
                d._validate_for_submission(row)
                raw=encode(row['bundle']);h=sha(raw)
                # Bypass both content and verified-result caches. A locally
                # saved/exported copy is never evidence of public storage.
                require(d.content.origin.get(h,MAX_BYTES)==raw,'direct-public-readback')
                final=d.index.anchor();d.index.finish(final)
                return {'scope':dict(d.scope),'bundle_hash':h,'calldata':submission_data(h),
                    'public_readback_checked':True,'payer_address_public':True}
        return super().dispatch(operation,body)
