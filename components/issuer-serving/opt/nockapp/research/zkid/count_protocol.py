"""Exact versioned post authorization for optional raw-count predicates."""
from count_pipeline import PROFILE
from count_policy import threshold
from policy import digest,hex_string,require,timestamp
from post_scope import payload

PROTOCOL='nockapp-base-count-post-v2'
FACTS={'account-controlled','followers-more-than','follower-count'}


def selection(facts,value):
    require(type(facts) is list and 1<=len(facts)<=3 and all(type(f) is str and f in FACTS for f in facts)
        and len(set(facts))==len(facts) and facts==sorted(facts),'count-facts')
    if 'followers-more-than' in facts:threshold(value)
    else:require(value is None,'follower-threshold')
    return {'facts':facts,'threshold':value}


def challenge(post,facts,value,app,chain,contract,sequence,now,submission):
    data=payload(post);require(post['claims']==[],'count-demo-claims')
    selected=selection(facts,value)
    require(type(app) is str and app.startswith('0x'),'count-application');hex_string(app[2:],64)
    require(type(contract) is str and contract.startswith('0x'),'count-contract');hex_string(contract[2:],40)
    require(type(chain) is int and chain in (31337,84532) and type(sequence) is int and 0<=sequence<2**53,'count-chain')
    timestamp(now);hex_string(submission,64)
    require(any(bytes.fromhex(submission)) and any(bytes.fromhex(app[2:]))
        and any(bytes.fromhex(contract[2:])),'count-context')
    import hashlib
    scope=digest({'profile':PROTOCOL,'application':app,'chain_id':chain,'contract':contract,
        'post_sha256':hashlib.sha256(data).hexdigest(),'selection':selected,'submission_id':submission})
    return {'profile':PROFILE,'nonce':submission,'scope':scope,'facts':facts,'threshold':value,'identity':False,
        'registry_sequence':sequence,'created_at':now,'expires_at':now+60}
