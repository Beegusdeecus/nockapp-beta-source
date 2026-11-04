"""Fixed EIP712 v5 authorization preceding final artifact-bound author proof."""
from authorship import nonzero_hex
from authorship_v5 import validate_core
from policy import canonical,digest,require,strict_json,timestamp
from public_bundle_v5 import blob,unblob,evidence_hash,validate_unsigned
from wallet_authorship import DOMAIN_FIELDS,root_hash,verify_signature,address
PROFILE='nockapp-wallet-post-authorization-v5'
PURPOSE='Authorize this exact NockApp post, its private author and selected public evidence'
FIELDS=[('purpose','string'),('application','bytes32'),('coreHash','bytes32'),('postAuthorHash','bytes32'),
    ('logicalAuthorHash','bytes32'),('followerEvidenceHash','bytes32'),('historyEvidenceHash','bytes32'),
    ('nonce','bytes32'),('issuedAt','uint256'),('deadline','uint256')]

def typed_data(u,nonce,created_at,expires_at):
    validate_unsigned(u);c=validate_core(u['core']);require(c['selection']['address'] is True,'v5-wallet-not-selected')
    nonzero_hex(nonce,64);timestamp(created_at);timestamp(expires_at);require(expires_at-created_at==60,'v5-wallet-window')
    x=c['context'];return {'types':{'EIP712Domain':DOMAIN_FIELDS,'NockAppPostAuthorizationV5':[{'name':n,'type':t} for n,t in FIELDS]},
        'primaryType':'NockAppPostAuthorizationV5','domain':{'name':'NockApp Private Authorship','version':'5','chainId':x['chain_id'],'verifyingContract':x['contract']},
        'message':{'purpose':PURPOSE,'application':x['application'],'coreHash':'0x'+digest(c),
            'postAuthorHash':root_hash(u['author']['exact']),'logicalAuthorHash':root_hash(u['author']['logical']),
            'followerEvidenceHash':evidence_hash(u['evidence']['followers'],'followers'),
            'historyEvidenceHash':evidence_hash(u['evidence']['history'],'history'),
            'nonce':'0x'+nonce,'issuedAt':created_at,'deadline':expires_at}}

def payload(account,signature,nonce,created_at,expires_at):
    return blob(canonical({'profile':PROFILE,'address':address(account),'signature':signature,'nonce':nonce,
        'created_at':created_at,'expires_at':expires_at}),'wallet')

def verify(u,indexed_at):
    raw=unblob(u['evidence']['wallet'],'wallet');v=strict_json(raw,max_bytes=4096)
    require(set(v)=={'profile','address','signature','nonce','created_at','expires_at'} and v['profile']==PROFILE
        and v['address']==address(v['address']),'v5-wallet-payload')
    data=typed_data(u,v['nonce'],v['created_at'],v['expires_at']);timestamp(indexed_at)
    require(v['created_at']<=indexed_at<v['expires_at'],'v5-wallet-expired')
    require(verify_signature(data,v['address'],v['signature']),'v5-wallet-signature')
    return v['address']
