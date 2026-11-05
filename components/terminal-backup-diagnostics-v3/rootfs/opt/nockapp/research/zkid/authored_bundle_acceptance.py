"""Protocol4 replicated receipts and independent mathematical evidence checks."""
import copy
import time
from authored_count import trust as count_trust,verify as verify_count
from base_protocol import sha,read,keccak
from bundle_acceptance import AUTH_FIELDS,creation_time
from count_receipts import observation
from count_state import count_view
from domain_pipeline import definition_hash
from policy import canonical,require
from public_bundle_v4 import encode,commitments,post_intent,kind
from public_storage import ReplicatedPublicStore
from wallet_authorship import verify_post_address

ZERO='0x'+'00'*32
TYPE_TEXT=('AuthoredBundleAuthorization(bytes32 application,uint256 protocolVersion,bytes32 issuerDefinition,'
    'bytes32 submissionId,bytes32 postId,bytes32 threadId,bytes32 bundleHash,bytes32 registryHash,'
    'uint64 registrySequence,uint64 createdAt,uint64 deadline,uint64 observedAt,uint64 credentialExpiry,'
    'uint64 signerEpoch,uint8 credentialKind)')


def authorization_digest(auth,app,definition,chain,contract):
    def word(v):return v.to_bytes(32,'big') if type(v) is int else bytes.fromhex(v.removeprefix('0x')).rjust(32,b'\0')
    domain=keccak(b''.join(word(v) for v in (keccak(b'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),
        keccak(b'NockApp Bundle Acceptance'),keccak(b'4'),chain,contract)))
    body=keccak(b''.join(word(v) for v in (keccak(TYPE_TEXT.encode()),app,4,definition,*[auth[k] for k in AUTH_FIELDS])))
    return keccak(b'\x19\x01'+bytes.fromhex(domain[2:])+bytes.fromhex(body[2:]))


def check_evidence(bundle,definition,author_native,count_native,when):
    encode(bundle);require(author_native is not None,'bundle-verifier-unavailable')
    i=post_intent(bundle);author=bundle['authorship']
    require(author_native.verify_post(i,author),'authored-bundle-author-rejected')
    result={'registryHash':ZERO,'registrySequence':0,'observedAt':0,'credentialExpiry':0,
        'disclosed_count':None,'authorship_checked':True,'address_checked':False,'public_address':None,
        'proof_deadlines':[]}
    if kind(bundle):
        require(count_native is not None,'bundle-verifier-unavailable')
        evidence=bundle['evidence'];view=evidence['issuer_view']
        require(view['definition_hash']==definition==definition_hash(view['public']),'authored-bundle-issuer-definition')
        projected=count_view(count_native,view)
        c=evidence['challenge'];t=count_trust(i,projected,c['created_at']);t['legacy']['now']=when
        require(c==t['legacy']['challenge'],'authored-bundle-proof-context')
        require(verify_count(author_native,evidence['presentation'],i,author,t),'authored-bundle-count-rejected')
        start,expiry,count=observation(evidence['presentation']);require(count is None,'authored-bundle-count-disclosed')
        result.update(registryHash=sha(canonical(view)),registrySequence=view['sequence'],observedAt=start,credentialExpiry=expiry)
        result['proof_deadlines'].extend([c['expires_at'],expiry])
    if bundle['selection']['address']:
        d=bundle['address_disclosure']
        require(verify_post_address(author_native,i,author,bundle['evidence'],d,when),'authored-bundle-wallet-rejected')
        result.update(address_checked=True,public_address=d['address'])
        result['proof_deadlines'].append(d['expires_at'])
    return result


class AuthoredBundleReceiptVerifier:
    def __init__(self,rpc,contract,registry,author_native,count_native,key,store,app,clock=None):
        require(isinstance(store,ReplicatedPublicStore),'bundle-replicated-storage-required')
        self.rpc,self.contract,self.registry,self.author_native,self.count_native,self.key,self.store,self.app=(
            rpc,contract,registry,author_native,count_native,key,store,app)
        self.clock=clock or (lambda:int(time.time()))

    def approve(self,bundle):
        bundle=copy.deepcopy(bundle);data=encode(bundle);c=bundle['context'];now=self.clock()
        require(c['application']==self.app and c['contract']==self.contract and c['chain_id']==int(self.rpc.call('eth_chainId'),16)
            and int(read(self.rpc,self.contract,'PROTOCOL_VERSION()'),16)==4,'authored-bundle-application')
        bound=commitments(bundle)
        require(read(self.rpc,self.contract,'accepted(bytes32)',bound['submissionId'])==ZERO,'authored-bundle-already-accepted')
        require(read(self.rpc,self.contract,'submissionsByPost(bytes32)',bound['postId'])==ZERO,'authored-bundle-duplicate-post')
        checked=check_evidence(bundle,self.registry.definition,self.author_native,self.count_native,now)
        view=bundle['evidence']['issuer_view'] if kind(bundle) else None
        if view is not None:require(self.registry.public_view()==view,'registry-state-changed')
        if bundle['post']['kind']=='comment':
            require(int(read(self.rpc,self.contract,'threads(bytes32)',commitments(bundle)['threadId']),16)==1,'bundle-thread-unavailable')
        stored=self.store.upload(bundle)
        end=self.clock();require(now<=end,'authored-bundle-clock')
        if view is not None:require(self.registry.public_view()==view,'registry-state-changed')
        created=creation_time(self.rpc,end)
        deadline=min([created+60,*checked['proof_deadlines']]);created=deadline-60
        require(end<deadline,'action-expired')
        auth={**commitments(bundle),'registryHash':checked['registryHash'],'registrySequence':checked['registrySequence'],
            'createdAt':created,'deadline':deadline,'observedAt':checked['observedAt'],'credentialExpiry':checked['credentialExpiry'],
            'signerEpoch':int(read(self.rpc,self.contract,'signerEpoch()'),16)}
        require(read(self.rpc,self.contract,'application()').lower()==self.app,'bundle-application')
        require('0x'+read(self.rpc,self.contract,'signer()')[-40:].lower()==self.key.address.lower(),'receipt-signer')
        signature=self.key.sign(authorization_digest(auth,self.app,self.registry.definition,c['chain_id'],self.contract))
        require(self.clock()<deadline,'action-expired')
        return {'authorization':auth,'signature':signature,'storage':stored,'bundle_hash':sha(data)}
