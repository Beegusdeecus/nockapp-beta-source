"""Versioned public authorization over UNCHANGED native anonymous proofs.

Local reference integration. Production requires approved measured signer code,
attested key enrollment and authenticated finalized-chain reads. No cloud calls.
"""
import copy
import hashlib
import json
import secrets
import subprocess
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from base_evm import encode, TOOLS
from domain_pipeline import PROFILE, definition_hash
from domain_posts import observation
from policy import POLICY_HASH, canonical, hex_string, require, strict_json
from post_scope import payload, facts

PROTOCOL = 'nockapp-base-post-v1'
AUTH_TYPE = '(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint256,uint256,uint256,uint256,uint256,uint256)'
AUTH_FIELDS = ('submissionId','postId','postHash','factsHash','proofHash','registryHash','registrySequence',
               'createdAt','deadline','observedAt','credentialExpiry','signerEpoch')
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
TYPE_TEXT = ('Authorization(bytes32 application,uint256 protocolVersion,bytes32 issuerDefinition,'
             'bytes32 submissionId,bytes32 postId,bytes32 postHash,bytes32 factsHash,bytes32 proofHash,bytes32 registryHash,'
             'uint256 registrySequence,uint256 createdAt,uint256 deadline,uint256 observedAt,'
             'uint256 credentialExpiry,uint256 signerEpoch)')


def keccak(data):
    # Pinned local implementation, never ask an RPC provider which bytes to sign.
    return subprocess.run([str(TOOLS/'cast'),'keccak','0x'+data.hex()],
        capture_output=True,check=True,timeout=10).stdout.decode().strip()


def authorization_digest(auth,app,definition,chain,contract):
    def word(value):
        if type(value) is int:return value.to_bytes(32,'big')
        data=bytes.fromhex(value.removeprefix('0x'))
        require(len(data)<=32,'authorization-word')
        return data.rjust(32,b'\0')
    domain=keccak(b''.join(word(x) for x in (
        keccak(b'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),
        keccak(b'NockApp Post Acceptance'),keccak(b'1'),chain,contract)))
    structure=keccak(b''.join(word(x) for x in (
        keccak(TYPE_TEXT.encode()),app,1,definition,*[auth[k] for k in AUTH_FIELDS])))
    return keccak(b'\x19\x01'+bytes.fromhex(domain[2:])+bytes.fromhex(structure[2:]))


def sha(data):
    return '0x'+hashlib.sha256(data).hexdigest()


def words(data):
    value = bytes.fromhex(data.removeprefix('0x'))
    require(len(value)%32==0,'abi-words')
    return [value[i:i+32] for i in range(0,len(value),32)]


def read(rpc, address, signature, *args):
    return rpc.call('eth_call',{'to':address,'data':encode(signature,*args)},'latest')


def auth_tuple(auth):
    require(set(auth)==set(AUTH_FIELDS),'authorization-schema')
    return '('+','.join(str(auth[k]) for k in AUTH_FIELDS)+')'


def scope_context(post, selected, app, chain, contract, submission):
    hex_string(submission,64);hex_string(app.removeprefix('0x'),64)
    require(type(chain) is int and chain>0 and type(contract) is str
            and len(contract)==42 and contract.startswith('0x'),'post-domain')
    hex_string(contract[2:].lower(),40)
    context = {'profile':PROTOCOL,'application':app.lower(),'chain_id':chain,
               'contract':contract.lower(),'protocol_version':1,'submission_id':submission,
               'post_sha256':sha(payload(post)),'facts':facts(selected)}
    return hashlib.sha256(canonical(context)).hexdigest()


def challenge(post, selected, app, chain, contract, sequence, now, submission=None):
    nonce = submission or secrets.token_hex(32)
    require(any(bytes.fromhex(nonce)),'submission-id')
    return {'profile':PROFILE,'nonce':nonce,'scope':scope_context(post,selected,app,chain,contract,nonce),
            'facts':facts(selected),'identity':False,'registry_sequence':sequence,
            'created_at':now,'expires_at':now+60}


class ReceiptKey:
    """Standard OpenSSL secp256k1; keys stay in memory. NOT an attestation.

    A production adapter must recover this key only in the approved workload.
    v is selected using the existing EVM ecrecover primitive, never custom ECC.
    """
    def __init__(self, rpc, key=None):
        self.rpc = rpc
        self.key = key or ec.generate_private_key(ec.SECP256K1())
        public = self.key.public_key().public_bytes(serialization.Encoding.X962,
                                                   serialization.PublicFormat.UncompressedPoint)
        self.address = '0x'+keccak(public[1:])[-40:]

    def sign(self, digest):
        data = bytes.fromhex(digest.removeprefix('0x'))
        r,s = utils.decode_dss_signature(self.key.sign(data,ec.ECDSA(utils.Prehashed(hashes.SHA256()))))
        s = min(s,ORDER-s)
        for v in (27,28):
            blob = data+v.to_bytes(32,'big')+r.to_bytes(32,'big')+s.to_bytes(32,'big')
            recovered = self.rpc.call('eth_call',{'to':'0x'+'0'*39+'1','data':'0x'+blob.hex()},'latest')
            if recovered.lower() == '0x'+'0'*24+self.address[2:].lower():
                return {'v':v,'r':f'0x{r:064x}','s':f'0x{s:064x}'}
        raise ValueError('signature-recovery-failed')


class ReceiptVerifier:
    """Public-proof-only handler; no action DB, issuer key or holder credential.

    The selected deployment co-locates this narrow handler in the issuer image.
    The same trust can forge credentials already. Separation of APIs/keys is
    still required. Signatures express this trust, not onchain native ZK checks.
    """
    def __init__(self,rpc,contract,registry,native,key,app,clock=None):
        self.rpc,self.contract,self.registry,self.native,self.key,self.app = rpc,contract,registry,native,key,app
        self.clock = clock or (lambda:int(time.time()))

    def approve(self,post,selected,c,proof):
        post,selected,c,proof = copy.deepcopy((post,selected,c,proof))
        started = time.monotonic(); now = self.clock()
        chain = int(self.rpc.call('eth_chainId'),16)
        view = self.registry.public_view()
        expected = challenge(post,selected,self.app,chain,self.contract,view['sequence'],c['created_at'],c['nonce'])
        require(c==expected and c['created_at']<=now<c['expires_at'],'post-context')
        require(proof.get('claimed_id') is None,'post-identity-disclosure')
        require(definition_hash(view['public'])==self.registry.definition,'issuer-definition')
        result = self.native.call('verify',public_input=proof,trust={
            'issuer':view['public'],'policy':POLICY_HASH,'challenge':c,
            'current_sequence':view['sequence'],'now':now})
        require(result.get('accepted') is True,'domain-proof-rejected')
        observed,expiry = observation(proof)
        require(self.registry.public_view()==view,'registry-state-changed')
        checked = self.clock()
        require(now<=checked and max(checked,now+time.monotonic()-started)<min(c['expires_at'],expiry),'action-expired')
        post_data = payload(post);fact_data = canonical(facts(selected))
        envelope = canonical({'profile':PROTOCOL,'challenge':c,'proof':proof})
        require(len(post_data)<=8192 and len(envelope)<=8192,'publication-size')
        auth = dict(zip(AUTH_FIELDS,[
            '0x'+c['nonce'],sha(post['id'].encode()),sha(post_data),sha(fact_data),sha(envelope),sha(canonical(view)),
            view['sequence'],c['created_at'],c['expires_at'],observed,expiry,
            int(read(self.rpc,self.contract,'signerEpoch()'),16)]))
        require(read(self.rpc,self.contract,'application()').lower()==self.app.lower(),'post-application')
        require('0x'+read(self.rpc,self.contract,'signer()')[-40:].lower()==self.key.address.lower(),'receipt-signer')
        digest = authorization_digest(auth,self.app,self.registry.definition,chain,self.contract)
        return {'authorization':auth,'signature':self.key.sign(digest),
                'post':post_data,'facts':fact_data,'proof_envelope':envelope}


def publication_data(package):
    s=package['signature']
    return encode('publish('+AUTH_TYPE+',bytes,bytes,bytes,uint8,bytes32,bytes32)',
                  auth_tuple(package['authorization']),*[ '0x'+package[k].hex()
                    for k in ('post','facts','proof_envelope')],s['v'],s['r'],s['s'])


def ordinary_publication_data(post, submission):
    """Explicit publication of one new ordinary post; never imports local history."""
    hex_string(submission,64)
    require(any(bytes.fromhex(submission)) and post['claims']==[],'ordinary-post')
    data=payload(post);require(len(data)<=8192,'publication-size')
    return encode('publishOrdinary(bytes32,bytes32,bytes)', '0x'+submission,
                  sha(post['id'].encode()), '0x'+data.hex())


def decode_post(post_bytes):
    value=json.loads(post_bytes)
    require(type(value) is list and len(value)==9,'publication-post')
    from post_scope import SCOPE
    require(value[0]==SCOPE,'publication-post')
    post=dict(zip(('kind','id','created_at','thread_id','title','body','references','claims'),value[1:]))
    require(payload(post)==post_bytes,'publication-canonical')
    return post


def publication_number(rpc,contract,log):
    value=rpc.call('eth_call',{'to':contract,'data':encode('postNumbers(bytes32)',log['topics'][1])},log['blockNumber'])
    number=int(value,16)
    require(0<number<=2**53-1,'publication-number')
    return str(number)


def dynamic_fields(data, indices):
    """Decode bytes fields from Solidity event data, with strict bounds."""
    blob=bytes.fromhex(data.removeprefix('0x')); result=[]
    for index in indices:
        require(32*(index+1)<=len(blob),'event-data')
        offset=int.from_bytes(blob[index*32:(index+1)*32],'big')
        require(offset%32==0 and offset+32<=len(blob),'event-data')
        size=int.from_bytes(blob[offset:offset+32],'big')
        require(offset+32+size<=len(blob),'event-data')
        result.append(blob[offset+32:offset+32+size])
    return result


def inspect_publication(rpc,contract,log,registry,native,app,now,finalized_number,*,count_native=None):
    """Independent read-only reconstruction. Never upgrades to a current badge.

    A changed global accumulator cannot identify which hidden credential was
    revoked. Preserve historical validity, and report current status UNKNOWN.
    """
    require(log['address'].lower()==contract.lower() and len(log['topics'])==3,'publication-event')
    ordinary=log['topics'][0]==keccak(b'OrdinaryPublished(bytes32,bytes32,bytes32,uint256,bytes)')
    require(ordinary or log['topics'][0]==keccak(b'Published(bytes32,bytes32,bytes32,uint256,bytes,bytes,bytes)'),
            'publication-event')
    require(not log.get('removed',False),'publication-orphaned')
    block=rpc.call('eth_getBlockByNumber',log['blockNumber'],False)
    require(block is not None and block['hash']==log['blockHash'],'publication-orphaned')
    require(int(log['blockNumber'],16)<=finalized_number,'publication-pending')
    receipt=rpc.call('eth_getTransactionReceipt',log['transactionHash'])
    require(receipt is not None and receipt['status']=='0x1' and receipt['blockHash']==log['blockHash']
            and log in receipt['logs'],'publication-receipt')
    if ordinary:
        post_bytes,=dynamic_fields(log['data'],(2,))
        require(sha(post_bytes)==log['topics'][2],'publication-content')
        post=decode_post(post_bytes)
        require(post['claims']==[] and sha(post['id'].encode())=='0x'+words(log['data'])[0].hex(),'ordinary-post')
        accepted_at=int.from_bytes(words(log['data'])[1],'big')
        require(type(now) is int and now>=accepted_at and int(block['timestamp'],16)==accepted_at,'publication-time')
        return {'post':post,'post_number':publication_number(rpc,contract,log),'facts':[],
                'valid_when_published':True,'accepted_at':accepted_at,'credential_status':'not-requested',
                'credential_expiry':None,'observed_at':None,'public_id':None,'laboratory_only':True}
    post_bytes,fact_bytes,envelope_bytes=dynamic_fields(log['data'],(2,3,4))
    require(sha(post_bytes)==log['topics'][2],'publication-content')
    parsed=strict_json(envelope_bytes);require(canonical(parsed)==envelope_bytes
        and set(parsed)=={'profile','challenge','proof'},'publication-proof')
    if parsed['profile']=='nockapp-base-count-post-v2':
        from count_receipts import inspect
        return inspect(rpc,contract,log,registry,count_native,app,now,block,post_bytes,fact_bytes,parsed)
    require(parsed['profile']==PROTOCOL,'publication-proof')
    post=decode_post(post_bytes)
    selected=json.loads(fact_bytes);require(canonical(facts(selected))==fact_bytes,'publication-facts')
    c=parsed['challenge'];require('0x'+c['nonce']==log['topics'][1],'publication-submission')
    chain=int(rpc.call('eth_chainId'),16)
    expected=challenge(post,selected,app,chain,contract,c['registry_sequence'],c['created_at'],c['nonce'])
    require(c==expected,'publication-context')
    # Obtain registry from canonical chain at the actual acceptance block.
    view=registry.public_at(log['blockNumber'],before=log)
    accepted_at=int.from_bytes(words(log['data'])[1],'big')
    require(type(now) is int and now>=accepted_at,'publication-clock')
    require(int(block['timestamp'],16)==accepted_at,'publication-time')
    require(view['sequence']==c['registry_sequence'],'publication-registry')
    result=native.call('verify',public_input=parsed['proof'],trust={'issuer':view['public'],
        'policy':POLICY_HASH,'challenge':c,'current_sequence':view['sequence'],'now':accepted_at})
    require(result.get('accepted') is True,'domain-proof-rejected')
    observed,expiry=observation(parsed['proof'])
    current=registry.public_view()
    current_status=('expired' if now>=expiry else 'valid-at-current-registry'
                    if current==view else 'unknown-after-registry-update')
    return {'post':post,'post_number':publication_number(rpc,contract,log),'facts':selected,'valid_when_published':True,'accepted_at':accepted_at,
            'credential_status':current_status,'credential_expiry':expiry,'observed_at':observed,
            'publication_registry_hash':sha(canonical(view)),
            'public_id':None,'laboratory_only':True}
