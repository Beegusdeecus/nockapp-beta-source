"""One separately generated, recoverable issuer-updater key; no issuer access.

Fresh KMS random seed reaches only the attested Recipient. A single immutable
selection stores its KMS ciphertext in a dedicated table key. No receipt,
sponsor, deployer or CA key is created. Public offers attest the durable winner.
Creation is an explicit administrative operation; recovery never creates.
"""
import base64
import copy
import re
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from base_key_vault import RecipientKeyVault
from base_protocol import ReceiptKey,keccak
from base_transactions import ProtectedSigner,hex_data
from domain_transport import _decode
from domain_trust import validate_approval as issuer_approval
from issuer_supervisor import validate_device
from policy import Rejected,canonical,digest,hex_string,require,strict_json
from trust import verify_aws_document,validate_pcrs

SCOPE='nockapp-public-updater-creation-scope-v1'
SELECTED='nockapp-public-updater-selected-v1'
PUBLIC='nockapp-public-updater-selection-v1'
PROPOSAL='nockapp-public-issuer-updater-proposal-v1'
OFFER='nockapp-public-updater-offer-v1'
APPROVAL='nockapp-public-updater-creation-approval-v1'
ORDER=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141


def scope(value):
    require(type(value) is dict and set(value)=={'profile','chain_id','definition','application','authority'}
        and value['profile']==SCOPE and type(value['chain_id']) is int and value['chain_id']==84532,'updater-key-scope')
    for name in ('definition','authority'):
        hex_string(value[name],64);require(any(bytes.fromhex(value[name])),'updater-key-scope')
    app=hex_data(value['application'],32)
    require(any(app) and value['application']=='0x'+app.hex(),'updater-key-scope')
    return copy.deepcopy(value)


def record_key(value):
    value=scope(value)
    return value['definition']+':action:public-updater-v1:'+digest(value)


def public_selection(value,expected):
    expected=scope(expected)
    require(type(value) is dict and set(value)=={'profile','scope','proposal','selection_sha256'}
        and value['profile']==PUBLIC and value['scope']==expected,'updater-selection-public')
    proposal=value['proposal']
    require(type(proposal) is dict and set(proposal)=={'profile','chain_id','definition','application','updater'}
        and proposal['profile']==PROPOSAL and proposal['chain_id']==expected['chain_id']
        and type(proposal['chain_id']) is int and proposal['definition']==expected['definition']
        and proposal['application']==expected['application'],'updater-selection-proposal')
    address=hex_data(proposal['updater'],20)
    require(any(address) and proposal['updater']=='0x'+address.hex(),'updater-selection-address')
    hex_string(value['selection_sha256'],64)
    return copy.deepcopy(value)


class RecoveredUpdater:
    def __init__(self,selection,key,rpc):self.public=copy.deepcopy(selection);self._key=key;self._rpc=rpc
    def signer(self):return ProtectedSigner(self._rpc,self._key)


class UpdaterCeremony:
    def __init__(self,nsm,vault,client,table,approved_scope,rpc):
        self.scope=scope(approved_scope)
        require(type(vault) is RecipientKeyVault and vault.nsm is nsm
            and vault.namespace==self.scope['definition'] and vault.authority==self.scope['authority']
            and vault.allowed==frozenset([canonical(self.scope)]),'updater-key-authority')
        require(type(table) is str and re.fullmatch(r'[A-Za-z0-9_.-]{3,255}',table),'updater-key-table')
        validate_device(nsm)
        require(rpc.call('eth_chainId')=='0x14a34','updater-key-chain')
        self.nsm,self.vault,self.client,self.table,self.rpc=nsm,vault,client,table,rpc
        self.aad=canonical(self.scope);self.key={'id':{'S':record_key(self.scope)}}

    def _validate(self,row):
        require(type(row) is dict and set(row)=={'profile','scope','proposal','wrapped_seed'}
            and row['profile']==SELECTED and row['scope']==self.scope,'updater-key-record')
        public_selection({'profile':PUBLIC,'scope':row['scope'],'proposal':row['proposal'],
            'selection_sha256':digest(row)},self.scope)
        _decode(row['wrapped_seed'],6144);return copy.deepcopy(row)

    def _head(self):
        response=self.client.get_item(TableName=self.table,Key=self.key,ConsistentRead=True)
        require(type(response) is dict,'updater-key-read');item=response.get('Item')
        if item is None:return None
        require(type(item) is dict and set(item)=={'id','data'} and item['id']==self.key['id']
            and type(item['data']) is dict and set(item['data'])=={'B'},'updater-key-head')
        raw=item['data']['B'];require(type(raw) is bytes and 0<len(raw)<=16384,'updater-key-head')
        value=strict_json(raw,max_bytes=16384);require(canonical(value)==raw,'updater-key-canonical')
        return self._validate(value)

    def _material(self,seed):
        require(type(seed) is bytes and len(seed)==32,'updater-key-seed')
        scalar=int.from_bytes(seed,'big')
        require(0<scalar<ORDER,'updater-key-scalar')  # No modulo bias or retry.
        return ReceiptKey(self.rpc,ec.derive_private_key(scalar,ec.SECP256K1()))

    def _recover(self,row):
        row=self._validate(row)
        seed,_=self.vault._key(self.aad,_decode(row['wrapped_seed'],6144))
        key=self._material(seed)
        require(key.address==row['proposal']['updater'],'updater-key-mismatch')
        selected=public_selection({'profile':PUBLIC,'scope':self.scope,'proposal':row['proposal'],
            'selection_sha256':digest(row)},self.scope)
        return RecoveredUpdater(selected,key,self.rpc)

    def recover(self,expected_selection_sha256=None):
        row=self._head();require(row is not None,'updater-key-selection-missing')
        if expected_selection_sha256 is not None:
            hex_string(expected_selection_sha256,64)
            require(digest(row)==expected_selection_sha256,'updater-key-selection-changed')
        return self._recover(row)

    def create(self):
        existing=self._head()
        if existing is not None:return self._recover(existing)
        seed,wrapped=self.vault._key(self.aad);key=self._material(seed)
        row=self._validate({'profile':SELECTED,'scope':self.scope,'proposal':{'profile':PROPOSAL,'chain_id':84532,
            'definition':self.scope['definition'],'application':self.scope['application'],'updater':key.address},
            'wrapped_seed':base64.b64encode(wrapped).decode()})
        self._recover(row)  # Prove actual Recipient recovery before committing.
        try:self.client.put_item(TableName=self.table,Item={**self.key,'data':{'B':canonical(row)}},
            ConditionExpression='attribute_not_exists(#id)',ExpressionAttributeNames={'#id':'id'})
        except Exception:
            observed=self._head();require(observed is not None,'updater-key-commit-unavailable')
            return self._recover(observed)
        observed=self._head();require(observed==row,'updater-key-commit-conflict')
        return self._recover(observed)

    def offer(self,nonce):
        hex_string(nonce,64);material=self.recover()
        public=material._key.key.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.CompressedPoint)
        binding={'profile':OFFER,'nonce':nonce,'selection':material.public,'code_identity':self.vault.code}
        document=self.nsm.attest(bytes.fromhex(nonce),public,bytes.fromhex(digest(binding)))
        require(type(document) is bytes and 0<len(document)<=32768,'updater-key-document')
        return {**binding,'public_key':public.hex(),'document':base64.b64encode(document).decode()}


def verify_offer(offer,nonce,approved):
    try:
        require(type(approved) is dict and set(approved)=={'profile','scope','code_identity','pcrs'}
            and approved['profile']==APPROVAL,'updater-key-approval')
        selected=scope(approved['scope'])
        issuer_approval({'mode':'production','definition_hash':selected['definition'],'state_authority_sha256':selected['authority'],
            'code_identity':approved['code_identity'],'pcrs':approved['pcrs']})
        hex_string(nonce,64)
        require(type(offer) is dict and set(offer)=={'profile','nonce','selection','code_identity','public_key','document'}
            and offer['profile']==OFFER and offer['nonce']==nonce and offer['code_identity']==approved['code_identity'],
            'updater-key-offer')
        output=public_selection(offer['selection'],selected);public=hex_data('0x'+offer['public_key'],33)
        require(offer['public_key']==public.hex(),'updater-key-public')
        key=ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(),public)
        uncompressed=key.public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
        require('0x'+keccak(uncompressed[1:])[-40:]==output['proposal']['updater'],'updater-key-public')
        binding={k:offer[k] for k in ('profile','nonce','selection','code_identity')}
        now=int(time.time()*1000);payload=verify_aws_document(_decode(offer['document'],32768),now)
        require(payload.get('nonce')==bytes.fromhex(nonce) and payload.get('public_key')==public
            and payload.get('user_data')==bytes.fromhex(digest(binding)) and type(payload.get('timestamp')) is int
            and now-120000<=payload['timestamp']<=now+5000,'updater-key-quote')
        validate_pcrs(payload['pcrs'],approved['pcrs']);return output
    except Exception:raise Rejected('updater-key-offer-rejected') from None
