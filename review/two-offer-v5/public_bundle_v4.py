"""Canonical protocol4 public bundles. Structural validation is not verification."""
import copy
from authorship import PROFILE as AUTHOR, intent,scopes,validate_intent,nonzero_hex
from base_protocol import sha
from domain_pipeline import definition_hash
from policy import canonical,hex_string,require,strict_json,timestamp
from post_scope import uuid

PROFILE='nockapp-public-discussion-bundle-v4'
ENCODING='canonical-ascii-json-v1'
MAX_BYTES=32768


def post_intent(value):return intent(value['post'],value['context'],disclose_address=value['selection']['address'],
    followers_threshold=value['selection']['followers_threshold'])


def kind(value):return 0 if value['selection']['followers_threshold'] is None else 2


def validate(value):
    require(type(value) is dict and set(value)=={'profile','encoding','context','post','selection','authorship','evidence','address_disclosure'}
        and value['profile']==PROFILE and value['encoding']==ENCODING,'authored-bundle-schema')
    selected=value['selection'];require(type(selected) is dict and set(selected)=={'address','followers_threshold'},'authored-bundle-selection')
    i=validate_intent(post_intent(value));p=value['post']
    if p['kind']=='comment':uuid(p['thread_id']);require(p['thread_id']!=p['id'],'authored-bundle-thread')
    proof=value['authorship']
    require(type(proof) is dict and set(proof)=={'profile','statements','response'} and proof['profile']==AUTHOR
        and type(proof['statements']) is list,'authored-bundle-author')
    expected=scopes(i);require(len(expected)==len(proof['statements']),'authored-bundle-author')
    hex_string(proof['response'],64);require(proof['response']==proof['response'].lower(),'authored-bundle-author')
    for statement,scope in zip(proof['statements'],expected):
        require(type(statement) is dict and set(statement)=={'scope','pseudonym','nonce_commitment'} and statement['scope']==scope,'authored-bundle-author')
        nonzero_hex(statement['pseudonym'],96);nonzero_hex(statement['nonce_commitment'],96)
    evidence=value['evidence']
    if kind(value)==0:require(evidence is None,'authored-bundle-ordinary')
    else:
        require(type(evidence) is dict and set(evidence)=={'issuer_view','challenge','presentation'},'authored-bundle-evidence')
        view=evidence['issuer_view'];require(type(view) is dict and set(view)=={'definition_hash','public','sequence'}
            and type(view['public']) is dict and type(view['sequence']) is int and 0<=view['sequence']<2**53
            and definition_hash(view['public'])==view['definition_hash'],'authored-bundle-issuer-view')
        require(set(view['public'])=={'id','schema','verifying_key','revocation_verifying_key','verifiable_encryption_key','revocation_registry'},
            'authored-bundle-public-issuer')
        pp=evidence['presentation']
        require(type(pp) is dict and set(pp)=={'profile','proof'} and pp['profile']=='nockapp-authored-count-presentation-v4'
            and type(pp['proof']) is dict and set(pp['proof'])=={'proofs','challenge','disclosed_messages'}
            and type(evidence['challenge']) is dict,'authored-bundle-count')
    d=value['address_disclosure']
    if not selected['address']:require(d is None,'authored-bundle-address-off')
    else:
        from wallet_authorship import address
        require(type(d) is dict and set(d)=={'address','signature','nonce','created_at','expires_at'}
            and address(d['address'])==d['address'],'authored-bundle-address')
        nonzero_hex(d['nonce'],64);timestamp(d['created_at']);timestamp(d['expires_at'])
        require(d['expires_at']-d['created_at']==60 and type(d['signature']) is str and d['signature'].startswith('0x'),'authored-bundle-address')
        hex_string(d['signature'][2:],130)
    require(len(canonical(value))<=MAX_BYTES,'authored-bundle-size');return value


def build(material):
    require(type(material) is dict and set(material)=={'intent','authorship','credential_evidence','address_disclosure'},'authored-bundle-material')
    i=validate_intent(material['intent'])
    return validate(copy.deepcopy({'profile':PROFILE,'encoding':ENCODING,'context':i['context'],'post':i['post'],
        'selection':i['disclosures'],'authorship':material['authorship'],'evidence':material['credential_evidence'],
        'address_disclosure':material['address_disclosure']}))


def encode(value):return canonical(validate(value))


def decode(data,expected_hash=None):
    value=validate(strict_json(data,max_bytes=MAX_BYTES));require(encode(value)==data,'authored-bundle-canonical')
    if expected_hash is not None:require(sha(data)==expected_hash,'authored-bundle-hash')
    return value


def commitments(value):
    data=encode(value);p=value['post'];root=p['id'] if p['kind']=='thread' else p['thread_id']
    return {'submissionId':'0x'+value['context']['submission_id'],'postId':sha(p['id'].encode()),
        'threadId':sha(root.encode()),'bundleHash':sha(data),'credentialKind':kind(value)}
