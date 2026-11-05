"""Protocol4 follower proof tied to the exact post's private author.

Caller must independently pin issuer definition/policy and verify canonical Base
registry state. This component alone makes no chain/finality/availability claim.
"""
from authorship import validate_intent
from count_policy import POLICY_HASH
from count_protocol import challenge
from policy import digest,require


def trust(value,issuer_view,now):
    validate_intent(value)
    threshold=value['disclosures']['followers_threshold'];require(threshold is not None,'authored-count-not-selected')
    c=value['context']
    selected=challenge(value['post'],['account-controlled','followers-more-than'],threshold,c['application'],
        c['chain_id'],c['contract'],issuer_view['sequence'],now,c['submission_id'])
    selected['scope']=digest(value)
    return {'legacy':{'issuer':issuer_view['public'],'policy':POLICY_HASH,'challenge':selected,
        'current_sequence':issuer_view['sequence'],'now':now},'intent_sha256':digest(value)}


def validate_trust(value,t):
    validate_intent(value);require(type(t) is dict and set(t)=={'legacy','intent_sha256'},'authored-count-trust')
    legacy=t['legacy'];require(type(legacy) is dict and set(legacy)=={'issuer','policy','challenge','current_sequence','now'},'authored-count-trust')
    view={'public':legacy['issuer'],'sequence':legacy['current_sequence']}
    expected=trust(value,view,legacy['challenge']['created_at'])
    expected['legacy']['now']=legacy['now']
    require(t==expected,'authored-count-trust')


def present(native,credential,value,author_proof,t):
    validate_trust(value,t);require(native.verify_post(value,author_proof),'authored-count-author')
    return native.call('present-count',credential=credential,trust=t,
        expected_author=author_proof['statements'][0]['pseudonym'])['presentation']


def verify(native,presentation,value,author_proof,t):
    validate_trust(value,t)
    if not native.verify_post(value,author_proof):return False
    return native.call('verify-count',public_input=presentation,trust=t,
        expected_author=author_proof['statements'][0]['pseudonym'])=={'accepted':True}
