"""Canonical public offchain bundle v3, separate from storage and acceptance.

Canonical bytes commit content, relationships, selected facts and public evidence.
Locations/acknowledgments are operational metadata, not part of public authority.
"""
import copy

from base_protocol import sha
from domain_pipeline import definition_hash
from policy import canonical,hex_string,require,strict_json
from post_scope import payload,uuid,facts as legacy_facts

PROFILE='nockapp-public-discussion-bundle-v3'
ENCODING='canonical-ascii-json-v1'
MAX_BYTES=32768


def validate_selection(chosen):
    require(type(chosen) is dict and set(chosen)=={'credential_kind','facts','threshold'}
        and type(chosen['credential_kind']) is int and chosen['credential_kind'] in (0,1,2),'bundle-selection')
    kind=chosen['credential_kind']
    if kind==0:require(chosen['facts']==[] and chosen['threshold'] is None,'bundle-ordinary')
    elif kind==1:
        require(legacy_facts(chosen['facts'])==chosen['facts'] and chosen['threshold'] is None,'bundle-selection')
    else:
        from count_protocol import selection
        selection(chosen['facts'],chosen['threshold'])
    return kind


def validate(value):
    if type(value) is dict and value.get("profile")=="nockapp-public-discussion-bundle-v4":
        from public_bundle_v4 import validate as authored
        return authored(value)
    require(type(value) is dict and set(value)=={'profile','encoding','context','post','selection','evidence'}
        and value['profile']==PROFILE and value['encoding']==ENCODING,'bundle-schema')
    context=value['context']
    require(type(context) is dict and set(context)=={'application','chain_id','contract','submission_id'}
        and type(context['chain_id']) is int and context['chain_id'] in (31337,84532),'bundle-context')
    for key,size in (('application',64),('contract',40)):
        text=context[key];require(type(text) is str and text.startswith('0x'),'bundle-context')
        hex_string(text[2:],size);require(any(bytes.fromhex(text[2:])),'bundle-context')
    hex_string(context['submission_id'],64);require(any(bytes.fromhex(context['submission_id'])),'bundle-context')
    post=value['post'];require(len(payload(post))<=8192 and post['claims']==[],'bundle-post')
    if post['kind']=='comment':uuid(post['thread_id']);require(post['thread_id']!=post['id'],'bundle-thread')
    chosen=value['selection']
    kind=validate_selection(chosen);evidence=value['evidence']
    if kind==0:
        require(chosen['facts']==[] and chosen['threshold'] is None and evidence is None,'bundle-ordinary')
    else:
        require(type(evidence) is dict and set(evidence)=={'issuer_view','challenge','proof'},'bundle-evidence')
        view=evidence['issuer_view']
        require(type(view) is dict and set(view)=={'definition_hash','public','sequence'}
            and type(view['public']) is dict and type(view['sequence']) is int and 0<=view['sequence']<2**53
            and definition_hash(view['public'])==view['definition_hash'],'bundle-issuer-view')
        require(set(view['public'])=={'id','schema','verifying_key','revocation_verifying_key',
            'verifiable_encryption_key','revocation_registry'},'bundle-public-issuer')
        proof=evidence['proof']
        require(type(proof) is dict and set(proof)=={'proof','claimed_id'} and proof['claimed_id'] is None
            and type(proof['proof']) is dict and set(proof['proof'])=={'proofs','challenge','disclosed_messages'}
            and type(evidence['challenge']) is dict,'bundle-public-proof')
    require(len(canonical(value))<=MAX_BYTES,'bundle-size');return value


def encode(value):return canonical(validate(value))


def decode(data,expected_hash=None):
    value=validate(strict_json(data,max_bytes=MAX_BYTES));require(encode(value)==data,'bundle-canonical')
    if expected_hash is not None:require(sha(data)==expected_hash,'bundle-hash')
    return value


def build(post,chosen,context,evidence=None):
    return validate(copy.deepcopy({'profile':PROFILE,'encoding':ENCODING,'context':context,'post':post,
        'selection':chosen,'evidence':evidence}))


def commitments(value):
    if type(value) is dict and value.get("profile")=="nockapp-public-discussion-bundle-v4":
        from public_bundle_v4 import commitments as authored
        return authored(value)
    data=encode(value);post=value['post'];root=post['id'] if post['kind']=='thread' else post['thread_id']
    return {'submissionId':'0x'+value['context']['submission_id'],'postId':sha(post['id'].encode()),
        'threadId':sha(root.encode()),'bundleHash':sha(data),'credentialKind':value['selection']['credential_kind']}
