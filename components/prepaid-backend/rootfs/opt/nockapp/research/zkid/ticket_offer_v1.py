"""Shared public ticket terms and exact blinded-pack commitments.

No production prices/deployment are selected here. An installer must pin the
complete manifest digest; a server cannot negotiate a per-buyer offer/key.
"""
import copy
import hashlib
import math
import re
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from policy import canonical, require, Rejected
from ticket_native_v1 import TicketProtocol, PROFILE, _decode

OFFER = 'nockapp-public-prepaid-offer-v1'
OFFER_V2 = 'nockapp-public-prepaid-offer-v2'
REFUNDS = 'unissued-only-durable-decision-v1'


def hex_value(value, size):
    require(type(value) is str and re.fullmatch('0x[0-9a-f]{'+str(size*2)+'}',value)
        and int(value,16)>0,'ticket-offer-hex')
    return value


def integer(value, maximum):
    require(type(value) is int and 0 < value <= maximum,'ticket-offer-integer')
    return value


def wei(value):
    require(type(value) is str and re.fullmatch(r'[1-9][0-9]{0,38}',value)
        and int(value)<2**128,'ticket-offer-wei')
    return int(value)


def terms(value):
    if type(value) is dict and value.get('profile')==OFFER_V2:
        require(value.get('redemption_ledger')=='nockapp-ticket-publication-ledger-v2','ticket-offer-ledger')
        legacy={k:v for k,v in value.items() if k!='redemption_ledger'}
        legacy['profile']=OFFER;terms(legacy)
        return value
    require(type(value) is dict and set(value)=={'profile','chain_id','application',
        'index_contract','index_runtime_keccak','ticket_spki','pack_size','pack_price_wei',
        'payment_recipient','purchase_before','redeem_before','max_bundle_bytes','max_gas',
        'max_total_fee_wei','refund_policy'},'ticket-offer-schema')
    require(value['profile']==OFFER and type(value['chain_id']) is int and value['chain_id']==84532,'ticket-offer-chain')
    hex_value(value['application'],32);hex_value(value['index_contract'],20)
    hex_value(value['index_runtime_keccak'],32);hex_value(value['payment_recipient'],20)
    public=_decode(value['ticket_spki'],1024)
    try:
        key=serialization.load_der_public_key(public)
        require(isinstance(key,rsa.RSAPublicKey) and key.key_size==3072 and key.public_numbers().e==65537
            and key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)==public,'ticket-public-key')
    except Rejected:raise
    except Exception:raise Rejected('ticket-public-key') from None
    integer(value['pack_size'],32);wei(value['pack_price_wei']);wei(value['max_total_fee_wei'])
    integer(value['purchase_before'],2**53-1);integer(value['redeem_before'],2**53-1)
    require(value['redeem_before']>value['purchase_before'],'ticket-offer-expiry')
    require(type(value['max_bundle_bytes']) is int and value['max_bundle_bytes']==65536,'ticket-offer-bundle-size')
    require(type(value['max_gas']) is int and 21000<=value['max_gas']<=1000000,'ticket-offer-gas')
    require(value['refund_policy']==REFUNDS,'ticket-offer-refunds')
    return value


def terms_hash(value):
    return '0x'+hashlib.sha256(b'nockapp-ticket-offer-terms-v1\0'+canonical(terms(value))).hexdigest()


def manifest_hash(value):
    require(type(value) is dict and set(value)=={'terms','purchase_contract','purchase_runtime_keccak'},'ticket-manifest-schema')
    terms(value['terms']);hex_value(value['purchase_contract'],20);hex_value(value['purchase_runtime_keccak'],32)
    return hashlib.sha256(b'nockapp-ticket-offer-manifest-v1\0'+canonical(value)).hexdigest()


class TicketOffer:
    def __init__(self,manifest,expected_hash,native):
        require(type(expected_hash) is str and re.fullmatch(r'[0-9a-f]{64}',expected_hash)
            and manifest_hash(manifest)==expected_hash,'ticket-manifest-pin')
        self.manifest=copy.deepcopy(manifest);self.terms=self.manifest['terms'];self.hash=expected_hash
        self.protocol=TicketProtocol(native,_decode(self.terms['ticket_spki'],1024),bytes.fromhex(self.hash))
        self.modulus=serialization.load_der_public_key(_decode(self.terms['ticket_spki'],1024)).public_numbers().n

    def check(self):
        require(self.terms is self.manifest['terms'] and manifest_hash(self.manifest)==self.hash,'ticket-manifest-changed')

    def pack(self,value):
        self.check()
        require(type(value) is dict and set(value)=={'profile','parameters','blinded'}
            and value['profile']==PROFILE and value['parameters']==self.hash
            and type(value['blinded']) is list and len(value['blinded'])==self.terms['pack_size'],'ticket-purchase-pack')
        for item in value['blinded']:
            data=_decode(item,384);number=int.from_bytes(data,'big')
            require(len(data)==384 and 0<number<self.modulus and math.gcd(number,self.modulus)==1,'ticket-purchase-pack')
        require(len(set(value['blinded']))==len(value['blinded']),'ticket-purchase-duplicates')
        require(len(canonical(value))<=32768,'ticket-purchase-size')
        return copy.deepcopy(value)

    def pack_hash(self,value):
        return '0x'+hashlib.sha256(b'nockapp-ticket-paid-pack-v1\0'+canonical(self.pack(value))).hexdigest()
