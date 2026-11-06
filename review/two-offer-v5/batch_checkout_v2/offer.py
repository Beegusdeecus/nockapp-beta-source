"""Explicit new offer scope for one-call payment; legacy offers stay untouched."""
import copy,hashlib,re
from cryptography.hazmat.primitives import serialization
from policy import canonical,require
from ticket_native_v1 import TicketProtocol,_decode
from ticket_offer_v1 import TicketOffer,terms as legacy_terms,OFFER_V2,hex_value,wei
from base_protocol import keccak

PROFILE='nockapp-public-prepaid-batch-offer-v3'
PACKS=25
VERSION=2

def terms(value):
    require(type(value) is dict and value.get('profile')==PROFILE
        and type(value.get('payment_receipt_version')) is int and value['payment_receipt_version']==VERSION
        and type(value.get('packs_per_payment')) is int and value['packs_per_payment']==PACKS
        and type(value.get('pack_size')) is int and value['pack_size']==2,'batch-offer-version')
    old={k:v for k,v in value.items()if k not in ('payment_receipt_version','packs_per_payment')}
    old['profile']=OFFER_V2;legacy_terms(old)
    wei(str(PACKS*int(value['pack_price_wei'])))
    return value

def terms_hash(value):
    return '0x'+hashlib.sha256(b'nockapp-ticket-offer-terms-v3\0'+canonical(terms(value))).hexdigest()

def manifest_hash(value):
    require(type(value) is dict and set(value)=={'terms','purchase_contract','purchase_runtime_keccak'},'batch-manifest-schema')
    terms(value['terms']);hex_value(value['purchase_contract'],20);hex_value(value['purchase_runtime_keccak'],32)
    return hashlib.sha256(b'nockapp-ticket-offer-manifest-v3\0'+canonical(value)).hexdigest()

class BatchOffer(TicketOffer):
    """New blinded-message parameters; never reinterpret a stored v1/v2 scope."""
    def __init__(self,manifest,expected_hash,native):
        require(type(expected_hash) is str and re.fullmatch('[0-9a-f]{64}',expected_hash)
            and manifest_hash(manifest)==expected_hash,'batch-manifest-pin')
        self.manifest=copy.deepcopy(manifest);self.terms=self.manifest['terms'];self.hash=expected_hash
        public=_decode(self.terms['ticket_spki'],1024)
        self.protocol=TicketProtocol(native,public,bytes.fromhex(self.hash))
        self.modulus=serialization.load_der_public_key(public).public_numbers().n
    def check(self):
        require(self.terms is self.manifest['terms'] and manifest_hash(self.manifest)==self.hash,'batch-manifest-changed')
    def transaction(self,packs):
        self.check()
        require(type(packs) is list and len(packs)==PACKS,'batch-packs')
        for pack in packs:hex_value(pack,32)
        require(len(set(packs))==PACKS,'batch-packs')
        return {'to':self.manifest['purchase_contract'],'value':hex(PACKS*int(self.terms['pack_price_wei'])),
            'data':keccak(b'buyBatch(bytes32[25])')[:10]+''.join(pack[2:]for pack in packs)}
