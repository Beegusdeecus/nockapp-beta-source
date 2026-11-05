"""Lean v3 receipts and independent public-bundle evidence verification.

The contract verifies an explicitly trusted attested-verifier receipt. Native
credential proofs are checked locally against committed public issuer evidence.
"""
import copy
import time

from base_evm import encode
from base_protocol import keccak,read,sha
from domain_pipeline import definition_hash
from policy import POLICY_HASH,canonical,require
from public_bundle import encode as bundle_bytes,commitments
from public_storage import ReplicatedPublicStore

AUTH_TYPE='(bytes32,bytes32,bytes32,bytes32,bytes32,uint64,uint64,uint64,uint64,uint64,uint64,uint8)'
AUTH_FIELDS=('submissionId','postId','threadId','bundleHash','registryHash','registrySequence','createdAt','deadline',
    'observedAt','credentialExpiry','signerEpoch','credentialKind')
TYPE_TEXT=('BundleAuthorization(bytes32 application,uint256 protocolVersion,bytes32 issuerDefinition,'
    'bytes32 submissionId,bytes32 postId,bytes32 threadId,bytes32 bundleHash,bytes32 registryHash,'
    'uint64 registrySequence,uint64 createdAt,uint64 deadline,uint64 observedAt,uint64 credentialExpiry,'
    'uint64 signerEpoch,uint8 credentialKind)')
ZERO='0x'+'00'*32


def creation_time(rpc,now):
    # A recent L2 head can lag wall time. Binding creation to a future timestamp
    # makes estimation fail before the next block; use the earlier known time.
    block=rpc.call('eth_getBlockByNumber','latest',False)
    require(type(block) is dict and type(block.get('timestamp')) is str,'bundle-chain-time')
    created=min(now,int(block['timestamp'],16))
    require(now<created+60,'action-expired')
    return created


def authorization_digest(auth,app,definition,chain,contract):
    def word(value):
        if type(value) is int:return value.to_bytes(32,'big')
        return bytes.fromhex(value.removeprefix('0x')).rjust(32,b'\0')
    domain=keccak(b''.join(word(x) for x in (keccak(b'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),
        keccak(b'NockApp Bundle Acceptance'),keccak(b'3'),chain,contract)))
    body=keccak(b''.join(word(x) for x in (keccak(TYPE_TEXT.encode()),app,3,definition,*[auth[k] for k in AUTH_FIELDS])))
    return keccak(b'\x19\x01'+bytes.fromhex(domain[2:])+bytes.fromhex(body[2:]))


def auth_tuple(auth):
    require(set(auth)==set(AUTH_FIELDS),'bundle-authorization-schema')
    return '('+','.join(str(auth[k]) for k in AUTH_FIELDS)+')'


def acceptance_data(package):
    signature=package['signature']
    return encode('accept('+AUTH_TYPE+',uint8,bytes32,bytes32)',auth_tuple(package['authorization']),
        signature['v'],signature['r'],signature['s'])


def check_evidence(bundle,definition,native,count_native,when):
    """Structural/content checks do not constitute credential proof acceptance."""
    bundle_bytes(bundle);chosen=bundle['selection'];kind=chosen['credential_kind']
    if kind==0:return {'registryHash':ZERO,'registrySequence':0,'observedAt':0,'credentialExpiry':0,'disclosed_count':None}
    evidence=bundle['evidence'];view=evidence['issuer_view'];c=evidence['challenge'];proof=evidence['proof']
    require(view['definition_hash']==definition==definition_hash(view['public']),'bundle-issuer-definition')
    context=bundle['context'];facts=chosen['facts']
    if kind==1:
        from base_protocol import challenge
        from domain_posts import observation
        expected=challenge(bundle['post'],facts,context['application'],context['chain_id'],context['contract'],
            view['sequence'],c['created_at'],context['submission_id'])
        require(native is not None,'bundle-verifier-unavailable')
        trust={'issuer':view['public'],'policy':POLICY_HASH,'challenge':c,'current_sequence':view['sequence'],'now':when}
        verifier=native
    else:
        from count_protocol import challenge
        from count_policy import POLICY_HASH as COUNT_POLICY
        from count_state import count_view
        from count_receipts import observation
        require(count_native is not None,'bundle-verifier-unavailable')
        expected=challenge(bundle['post'],facts,chosen['threshold'],context['application'],context['chain_id'],context['contract'],
            view['sequence'],c['created_at'],context['submission_id'])
        projected=count_view(count_native,view)
        trust={'issuer':projected['public'],'policy':COUNT_POLICY,'challenge':c,'current_sequence':view['sequence'],'now':when}
        verifier=count_native
    require(c==expected,'bundle-proof-context')
    require(verifier.call('verify',public_input=proof,trust=trust).get('accepted') is True,'bundle-credential-rejected')
    observed=observation(proof)
    return {'registryHash':sha(canonical(view)),'registrySequence':view['sequence'],
        'observedAt':observed[0],'credentialExpiry':observed[1],
        'disclosed_count':observed[2] if kind==2 else None}


class BundleReceiptVerifier:
    def __init__(self,rpc,contract,registry,native,count_native,key,store,app,clock=None):
        require(isinstance(store,ReplicatedPublicStore),'bundle-replicated-storage-required')
        (self.rpc,self.contract,self.registry,self.native,self.count_native,self.key,self.store,self.app)=(
            rpc,contract,registry,native,count_native,key,store,app)
        self.clock=clock or (lambda:int(time.time()))

    def approve(self,bundle):
        bundle=copy.deepcopy(bundle);data=bundle_bytes(bundle);context=bundle['context'];now=self.clock()
        require(context['application']==self.app and context['contract']==self.contract
            and context['chain_id']==int(self.rpc.call('eth_chainId'),16),'bundle-application')
        checked=check_evidence(bundle,self.registry.definition,self.native,self.count_native,now)
        kind=bundle['selection']['credential_kind'];view=bundle['evidence']['issuer_view'] if kind else None
        if kind:require(self.registry.public_view()==view,'registry-state-changed')
        if bundle['post']['kind']=='comment':
            require(int(read(self.rpc,self.contract,'threads(bytes32)',commitments(bundle)['threadId']),16)==1,
                'bundle-thread-unavailable')
        # Invalid evidence is rejected before paying for uploads. Both durable
        # acknowledgments and exact readbacks precede ANY acceptance signature.
        stored=self.store.upload(bundle)
        end=self.clock()
        if kind:
            require(self.registry.public_view()==view,'registry-state-changed')
            c=bundle['evidence']['challenge'];created,deadline=c['created_at'],c['expires_at']
            require(now<=end<min(deadline,checked['credentialExpiry']),'action-expired')
        else:created=creation_time(self.rpc,end);deadline=created+60
        auth={**commitments(bundle),'registryHash':checked['registryHash'],'registrySequence':checked['registrySequence'],
            'createdAt':created,'deadline':deadline,'observedAt':checked['observedAt'],
            'credentialExpiry':checked['credentialExpiry'],'signerEpoch':int(read(self.rpc,self.contract,'signerEpoch()'),16)}
        require(read(self.rpc,self.contract,'application()').lower()==self.app,'bundle-application')
        require('0x'+read(self.rpc,self.contract,'signer()')[-40:].lower()==self.key.address.lower(),'receipt-signer')
        signature=self.key.sign(authorization_digest(auth,self.app,self.registry.definition,context['chain_id'],self.contract))
        require(self.clock()<deadline,'action-expired')
        return {'authorization':auth,'signature':signature,'storage':stored,'bundle_hash':sha(data)}
