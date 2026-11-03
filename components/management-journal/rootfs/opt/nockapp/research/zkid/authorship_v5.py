"""Protocol5 core scopes and final artifact-bound G1 authorship.

Reuses the pinned generic G1 worker, never a public G2 holder key. No wallet,
keyring, network, issuer database or permanent identity is accessed here.
"""
import copy
from authorship import nonzero_hex,PROFILE as PROOF_PROFILE
from count_policy import MAX_COUNT
from policy import canonical,digest,require,timestamp
from post_scope import payload,uuid

CORE='nockapp-post-core-v5'
AUTH='nockapp-final-authorship-context-v5'

def address(v):
    require(type(v) is str and v.startswith('0x'),'v5-address');nonzero_hex(v[2:],40);return v

def hash32(v):
    require(type(v) is str and v.startswith('0x'),'v5-hash');nonzero_hex(v[2:],64);return v

def reference(v,*,historical=False):
    require(type(v) is dict and set(v)=={'protocol','chain_id','contract','number','bundle_hash'}
        and type(v['protocol']) is int and v['protocol'] in (4,5)
        and type(v['chain_id']) is int and v['chain_id'] in (31337,84532),'v5-reference')
    address(v['contract']);hash32(v['bundle_hash']);n=v['number']
    require((n is None and not historical) or (type(n) is str and n.isascii() and n.isdigit()
        and n==str(int(n)) and 0<int(n)<2**53),'v5-reference')
    return v

def wire_projection(core):
    p=core['post']
    return {**p,'thread_id':None if p['kind']=='thread' else digest(core['thread']),'claims':[]}

def validate_core(c):
    require(type(c) is dict and set(c)=={'profile','context','post','thread','references','selection'} and c['profile']==CORE,'v5-core')
    x=c['context'];require(type(x) is dict and set(x)=={'protocol','chain_id','application','contract','submission_id'}
        and type(x['protocol']) is int and x['protocol']==5 and type(x['chain_id']) is int and x['chain_id'] in (31337,84532),'v5-context')
    hash32(x['application']);address(x['contract']);nonzero_hex(x['submission_id'],64)
    p=c['post'];require(type(p) is dict and set(p)=={'kind','id','created_at','title','body','references'},'v5-post')
    uuid(p['id']);timestamp(p['created_at'])
    require(p['kind'] in ('thread','comment') and ((p['kind']=='thread')==(c['thread'] is None)),'v5-thread')
    if c['thread'] is not None:
        reference(c['thread']);require(c['thread']['protocol']==5 and c['thread']['chain_id']==x['chain_id']
            and c['thread']['contract']==x['contract'],'v5-thread')
    require(type(c['references']) is list and len(c['references'])<=32,'v5-references')
    for ref in c['references']:reference(ref,historical=True)
    require(len({digest(r) for r in c['references']})==len(c['references']),'v5-references')
    s=c['selection'];require(type(s) is dict and set(s)=={'address','followers_threshold'} and type(s['address']) is bool
        and (s['followers_threshold'] is None or type(s['followers_threshold']) is int and 0<=s['followers_threshold']<=MAX_COUNT),'v5-selection')
    require(len(payload(wire_projection(c)))<=8192 and len(canonical(c))<=16384,'v5-post-size')
    return c

def core(post,context,*,thread=None,references=None,address_disclosure=False,followers_threshold=None):
    return validate_core(copy.deepcopy({'profile':CORE,'context':context,'post':post,'thread':thread,'references':references or [],
        'selection':{'address':address_disclosure,'followers_threshold':followers_threshold}}))

def scopes(c):
    validate_core(c);x=c['context']
    return [{'kind':'post','intent_sha256':digest({'profile':'nockapp-exact-post-scope-v5','core':c})},
        {'kind':'post','intent_sha256':digest({'profile':'nockapp-logical-post-scope-v5',
            'chain_id':x['chain_id'],'application':x['application'],'contract':x['contract'],'post_uuid':c['post']['id']})}]

def points(native,secret,c):
    a,b=[native.call('pseudonym',secret=secret,scope=s)['pseudonym'] for s in scopes(c)]
    return {'exact':a,'logical':b}

def final_context(unsigned):return digest({'profile':AUTH,'unsigned':unsigned})

def proof_shape(proof,expected):
    require(type(proof) is dict and set(proof)=={'profile','statements','response'} and proof['profile']==PROOF_PROFILE
        and type(proof['statements']) is list and len(proof['statements'])==len(expected),'v5-author-proof')
    nonzero_hex(proof['response'],64)
    for st,scope in zip(proof['statements'],expected):
        require(type(st) is dict and set(st)=={'scope','pseudonym','nonce_commitment'} and st['scope']==scope,'v5-author-proof')
        nonzero_hex(st['pseudonym'],96);nonzero_hex(st['nonce_commitment'],96)

def prove(native,secret,unsigned):
    from public_bundle_v5 import validate_unsigned
    validate_unsigned(unsigned);ss=scopes(unsigned['core'])
    p=native.call('prove',secret=secret,scopes=ss,context=final_context(unsigned))['proof']
    require(verify(native,unsigned,p),'v5-author-mismatch');return p

def verify(native,unsigned,proof):
    from public_bundle_v5 import validate_unsigned
    validate_unsigned(unsigned);ss=scopes(unsigned['core']);proof_shape(proof,ss)
    require([s['pseudonym'] for s in proof['statements']]==[unsigned['author']['exact'],unsigned['author']['logical']],'v5-author-mismatch')
    return native.call('verify',proof=proof,scopes=ss,context=final_context(unsigned))=={'accepted':True}

def logical_key(unsigned):
    return digest({'profile':'nockapp-logical-record-key-v5','scope':scopes(unsigned['core'])[1],'point':unsigned['author']['logical']})
