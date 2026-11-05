"""Serving store with bounded public history and unchanged encrypted-state CAS.

Only the fixed renewal service uses this adapter. Ciphertext reads/writes,
signed transactions, confirmed-block checks and boot fences remain inherited.
One exact-block public event replaces whole-history log download; no new table,
public snapshot cache in DynamoDB, initialization or rollback claim is added.
RPC authenticity/finality and durable managed storage remain trust dependencies.
"""
import re

from base_protocol import sha,keccak
from base_state import ChainIssuerStore
from fixed_issuer_code_v1 import runtime as fixed_runtime
from policy import canonical,require
from public_issuer_views import PublicIssuerViews
from renewal_transport_v3 import identity


class BoundedIssuerStore(ChainIssuerStore):
    def __init__(self,rpc,expected,objects):
        expected=identity(expected)
        super().__init__(rpc,expected['registry'],expected['updater'],objects,expected['definition_hash'])
        self.views=PublicIssuerViews(rpc,self.contract,
            keccak(fixed_runtime(expected['updater'],self.definition)),self.updater,self.definition,0,
            index_contract=expected['contract'])

    def public_at(self,block='latest',before=None):
        # Same-block publication ordering is the independent reader's at(record)
        # operation. This private serving interface only needs complete heads.
        require(before is None,'bounded-issuer-use-indexed-record-for-ordering')
        require(type(block) is str and (block in ('latest','finalized') or
            re.fullmatch(r'0x(?:0|[1-9a-f][0-9a-f]*)',block)),'bounded-issuer-block')
        anchor=self.rpc.call('eth_getBlockByNumber',block,False)
        require(type(anchor) is dict and type(anchor.get('number')) is str
            and re.fullmatch(r'0x(?:0|[1-9a-f][0-9a-f]*)',anchor['number']),'bounded-issuer-block')
        tag=anchor['number'];head=self.head(tag)
        require(head['initialized'],'registry-missing')
        public=self.views.current(anchor)
        require(sha(canonical(public))==head['registry'] and public['sequence']==head['sequence']
            and self.head(tag)==head,'registry-state-changed')
        # Retain the old store's lease/confirmed-block rejection even on a cache
        # hit, and ensure the chosen numeric anchor was not replaced meanwhile.
        require(self.rpc.call('eth_getBlockByNumber',tag,False)['hash']==anchor['hash'],'bounded-issuer-anchor-changed')
        return public
