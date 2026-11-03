"""Base/MetaMask EIP712 bindings to the exact private-authorship key/proof.

Component only. No provider requests, signing keys, wallet connection, transaction
or permission grant. Verification uses pinned local cast, without an RPC service.
"""
import hashlib
import subprocess
from authorship import (OWNERSHIP,context as validate_context,nonzero_hex,ownership_challenge,validate_intent)
from base_protocol import ORDER,TOOLS,keccak
from policy import canonical,digest,require,timestamp

DOMAIN_FIELDS=[{'name':'name','type':'string'},{'name':'version','type':'string'},
    {'name':'chainId','type':'uint256'},{'name':'verifyingContract','type':'address'}]
NAME='NockApp Private Authorship'
PURPOSE_OWNERSHIP='Bind this private signing identity to this NockApp credential request'
PURPOSE_POST='Authorize this exact NockApp post and its selected public proofs'


def address(value):
    require(type(value) is str and len(value)==42 and value.startswith('0x'),'wallet-address')
    nonzero_hex(value[2:].lower(),40)
    return value.lower()


def root_hash(root):
    nonzero_hex(root,96)
    return '0x'+hashlib.sha256(bytes.fromhex(root)).hexdigest()


def typed_data(primary,where,message,fields):
    validate_context(where)
    return {'types':{'EIP712Domain':DOMAIN_FIELDS,primary:[{'name':n,'type':t} for n,t in fields]},
        'primaryType':primary,'domain':{'name':NAME,'version':'4','chainId':where['chain_id'],
            'verifyingContract':where['contract']},'message':message}


def ownership_data(challenge,where,root):
    require(type(challenge) is dict and set(challenge)=={'profile','purpose','nonce','request_sha256','audience',
        'created_at','expires_at'},'wallet-ownership-challenge')
    require(challenge==ownership_challenge(challenge['nonce'],challenge['request_sha256'],challenge['audience'],
        challenge['created_at'],challenge['expires_at']),'wallet-ownership-challenge')
    return typed_data('NockAppIdentityOwnership',where,{
        'purpose':PURPOSE_OWNERSHIP,'application':where['application'],'identityKeyHash':root_hash(root),
        'requestHash':'0x'+challenge['request_sha256'],'audience':'0x'+challenge['audience'],
        'nonce':'0x'+challenge['nonce'],'issuedAt':challenge['created_at'],'deadline':challenge['expires_at']},
        [('purpose','string'),('application','bytes32'),('identityKeyHash','bytes32'),('requestHash','bytes32'),
         ('audience','bytes32'),('nonce','bytes32'),('issuedAt','uint256'),('deadline','uint256')])


def post_data(value,proof,credential_evidence,nonce,created_at,expires_at):
    validate_intent(value);nonzero_hex(nonce,64);timestamp(created_at);timestamp(expires_at)
    require(value['disclosures']['address'] is True and expires_at-created_at==60,'wallet-post-selection')
    from authorship import post_scope
    require(type(proof) is dict and type(proof.get('statements')) is list and len(proof['statements'])==1
        and proof['statements'][0]['scope']==post_scope(value),'wallet-post-proof')
    post_author=proof['statements'][0]['pseudonym']
    return typed_data('NockAppPostAuthorization',value['context'],{
        'purpose':PURPOSE_POST,'application':value['context']['application'],'postAuthorHash':root_hash(post_author),
        'intentHash':'0x'+digest(value),'authorshipProofHash':'0x'+digest(proof),
        'credentialEvidenceHash':'0x'+digest(credential_evidence),'nonce':'0x'+nonce,'issuedAt':created_at,'deadline':expires_at},
        [('purpose','string'),('application','bytes32'),('postAuthorHash','bytes32'),('intentHash','bytes32'),
         ('authorshipProofHash','bytes32'),('credentialEvidenceHash','bytes32'),('nonce','bytes32'),('issuedAt','uint256'),('deadline','uint256')])


def signing_digest(data):
    """Only this module's fixed, flat EIP712 schemas; no wallet-supplied types."""
    def structure(name,fields,values):
        words=[bytes.fromhex(keccak((name+'('+','.join(f['type']+' '+f['name'] for f in fields)+')').encode())[2:])]
        require(set(values)=={f['name'] for f in fields},'wallet-typed-fields')
        for f in fields:
            v=values[f['name']];kind=f['type']
            if kind=='string':words.append(bytes.fromhex(keccak(v.encode())[2:]))
            elif kind=='uint256':
                require(type(v) is int and 0<=v<2**256,'wallet-typed-integer');words.append(v.to_bytes(32,'big'))
            elif kind=='address':words.append(bytes(12)+bytes.fromhex(address(v)[2:]))
            elif kind=='bytes32':
                require(type(v) is str and v.startswith('0x'),'wallet-typed-bytes');nonzero_hex(v[2:],64);words.append(bytes.fromhex(v[2:]))
            else:require(False,'wallet-typed-type')
        return bytes.fromhex(keccak(b''.join(words))[2:])
    domain=structure('EIP712Domain',DOMAIN_FIELDS,data['domain'])
    primary=data['primaryType'];body=structure(primary,data['types'][primary],data['message'])
    return keccak(b'\x19\x01'+domain+body)


def verify_signature(data,account,signature):
    account=address(account)
    require(type(signature) is str and signature.startswith('0x') and len(signature)==132,'wallet-signature')
    try:raw=bytes.fromhex(signature[2:])
    except ValueError:require(False,'wallet-signature')
    r=int.from_bytes(raw[:32],'big');s=int.from_bytes(raw[32:64],'big');v=raw[64]
    require(0<r<ORDER and 0<s<=ORDER//2 and v in (0,1,27,28),'wallet-signature')
    normalized='0x'+(raw[:64]+bytes([v+27 if v<2 else v])).hex()
    done=subprocess.run([str(TOOLS/'cast'),'wallet','verify','--no-hash','--address',account,
        signing_digest(data),normalized],capture_output=True,timeout=10,
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C','RAYON_NUM_THREADS':'2'})
    return done.returncode==0 and not done.stderr and done.stdout.lower()==(
        'Validation succeeded. Address '+account+' signed this message.\n').lower().encode()


def verify_ownership(native,challenge,where,root,proof,account,signature,now):
    timestamp(now);data=ownership_data(challenge,where,root)
    require(challenge['created_at']<=now<challenge['expires_at'],'wallet-ownership-expired')
    if native.call('verify',proof=proof,scopes=[{'kind':'signing-identity'}],context=digest(challenge))!={'accepted':True}:return False
    if proof['statements'][0]['pseudonym']!=root:return False
    return verify_signature(data,account,signature)


def verify_post_address(native,value,proof,credential_evidence,disclosure,accepted_at):
    require(type(disclosure) is dict and set(disclosure)=={'address','signature','nonce','created_at','expires_at'},'wallet-disclosure')
    if not native.verify_post(value,proof):return False
    data=post_data(value,proof,credential_evidence,disclosure['nonce'],disclosure['created_at'],disclosure['expires_at'])
    timestamp(accepted_at)
    require(disclosure['created_at']<=accepted_at<disclosure['expires_at'],'wallet-post-expired')
    return verify_signature(data,disclosure['address'],disclosure['signature'])


def history_data(material,challenge,proof):
    """Fresh wallet endorsement of a selected-history claim, not retroactive
    evidence that this wallet signed each original post at publication time."""
    from authorship import selected_challenge
    require(type(material) is dict and set(material)=={'scope','numbers','bundle_hashes','intents','post_proofs','checkpoint'},'wallet-history-material')
    expected=selected_challenge(material['intents'],challenge['nonce'],challenge['audience'],challenge['created_at'],
        challenge['expires_at'],disclose_address=True)
    require(challenge==expected and len(material['numbers'])==len(material['bundle_hashes'])==len(material['intents']),'wallet-history-challenge')
    scope=material['scope']
    where={k:scope[k] for k in ('protocol','chain_id','application','contract')}|{'submission_id':challenge['nonce']}
    return typed_data('NockAppSelectedAuthorship',where,{
        'purpose':'Endorse only this selected NockApp authorship claim with this wallet address',
        'application':scope['application'],'selectionHash':'0x'+digest({'scope':scope,'numbers':material['numbers'],
            'bundle_hashes':material['bundle_hashes']}),'claimHash':'0x'+digest(challenge),'authorProofHash':'0x'+digest(proof),
        'nonce':'0x'+challenge['nonce'],'issuedAt':challenge['created_at'],'deadline':challenge['expires_at']},
        [('purpose','string'),('application','bytes32'),('selectionHash','bytes32'),('claimHash','bytes32'),
         ('authorProofHash','bytes32'),('nonce','bytes32'),('issuedAt','uint256'),('deadline','uint256')])
