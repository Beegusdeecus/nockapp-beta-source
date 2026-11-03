"""Count-v2 public proof verification and existing Base receipt integration.

The onchain receipt encoding stays v1. Its facts/proof hashes bind the complete
versioned v2 selection/envelope; ordinary and v1 posts keep the same global IDs.
"""
import copy
import time

from base_protocol import (AUTH_FIELDS,authorization_digest,decode_post,publication_number,read,sha,words)
from count_policy import MAX_COUNT,POLICY_HASH
from count_protocol import PROTOCOL,challenge,selection
from count_state import count_view
from policy import canonical,require,timestamp
from post_scope import payload


def observation(proof):
    """Read only after verifying this exact count-v2 native proof."""
    def pairs(value):
        require(type(value) is list and all(type(p) is list and len(p)==2 and type(p[0]) is str for p in value),
            'count-proof-shape')
        result=dict(value);require(len(result)==len(value),'count-proof-shape');return result
    disclosed=pairs(proof['proof']['disclosed_messages'])
    require(set(disclosed)=={'credential'},'count-proof-shape');claims=pairs(disclosed['credential'])
    def number(label):
        value=claims[label]
        require(type(value) is dict and set(value)=={'Number'} and type(value['Number']) is dict
            and set(value['Number'])=={'value'} and type(value['Number']['value']) is int,'count-proof-shape')
        return value['Number']['value']
    start,expiry=number('start'),number('expiry');timestamp(start);timestamp(expiry)
    require(start%3600==0 and expiry-start==86400,'count-proof-shape')
    count=number('follower_count') if 'follower_count' in claims else None
    require(count is None or 0<=count<=MAX_COUNT,'count-proof-shape')
    return start,expiry,count


class CountReceiptVerifier:
    """Public-proof handler; retains only the existing protected receipt key."""
    def __init__(self,base,native):
        self.base,self.native=base,native

    def approve(self,post,facts,threshold,c,proof):
        post,facts,c,proof=copy.deepcopy((post,facts,c,proof));base=self.base
        selected=selection(facts,threshold);started=time.monotonic();now=base.clock()
        chain=int(base.rpc.call('eth_chainId'),16);legacy=base.registry.public_view()
        view=count_view(self.native,legacy)
        expected=challenge(post,facts,threshold,base.app,chain,base.contract,view['sequence'],c['created_at'],c['nonce'])
        require(c==expected and c['created_at']<=now<c['expires_at'],'post-context')
        require(proof.get('claimed_id') is None,'post-identity-disclosure')
        checked=self.native.call('verify',public_input=proof,trust={'issuer':view['public'],'policy':POLICY_HASH,
            'challenge':c,'current_sequence':view['sequence'],'now':now})
        require(checked.get('accepted') is True,'count-proof-rejected')
        observed,expiry,_=observation(proof)
        require(base.registry.public_view()==legacy,'registry-state-changed')
        end=base.clock()
        require(now<=end and max(end,now+time.monotonic()-started)<min(c['expires_at'],expiry),'action-expired')
        post_data=payload(post);fact_data=canonical(selected)
        envelope=canonical({'profile':PROTOCOL,'challenge':c,'proof':proof})
        require(len(post_data)<=8192 and len(envelope)<=8192,'publication-size')
        auth=dict(zip(AUTH_FIELDS,['0x'+c['nonce'],sha(post['id'].encode()),sha(post_data),sha(fact_data),
            sha(envelope),sha(canonical(legacy)),legacy['sequence'],c['created_at'],c['expires_at'],observed,expiry,
            int(read(base.rpc,base.contract,'signerEpoch()'),16)]))
        require(read(base.rpc,base.contract,'application()').lower()==base.app.lower(),'post-application')
        require('0x'+read(base.rpc,base.contract,'signer()')[-40:].lower()==base.key.address.lower(),'receipt-signer')
        digest=authorization_digest(auth,base.app,base.registry.definition,chain,base.contract)
        return {'authorization':auth,'signature':base.key.sign(digest),'post':post_data,'facts':fact_data,'proof_envelope':envelope}


def inspect(rpc,contract,log,registry,native,app,now,block,post_bytes,fact_bytes,parsed):
    """Called after base inspector checks event, receipt, block and content hash."""
    require(native is not None,'count-verifier-unavailable')
    require(parsed['profile']==PROTOCOL,'count-publication-profile')
    from policy import strict_json
    selected=strict_json(fact_bytes)
    require(set(selected)=={'facts','threshold'} and canonical(selection(selected['facts'],selected['threshold']))==fact_bytes,
        'count-publication-facts')
    post=decode_post(post_bytes);c=parsed['challenge']
    require('0x'+c['nonce']==log['topics'][1],'publication-submission')
    expected=challenge(post,selected['facts'],selected['threshold'],app,int(rpc.call('eth_chainId'),16),
        contract,c['registry_sequence'],c['created_at'],c['nonce'])
    require(c==expected,'publication-context')
    legacy=registry.public_at(log['blockNumber'],before=log);view=count_view(native,legacy)
    accepted_at=int.from_bytes(words(log['data'])[1],'big')
    require(type(now) is int and now>=accepted_at and int(block['timestamp'],16)==accepted_at,'publication-time')
    require(view['sequence']==c['registry_sequence'],'publication-registry')
    checked=native.call('verify',public_input=parsed['proof'],trust={'issuer':view['public'],'policy':POLICY_HASH,
        'challenge':c,'current_sequence':view['sequence'],'now':accepted_at})
    require(checked.get('accepted') is True,'count-proof-rejected')
    observed,expiry,disclosed=observation(parsed['proof']);current=registry.public_view()
    status='expired' if now>=expiry else 'valid-at-current-registry' if current==legacy else 'unknown-after-registry-update'
    return {'post':post,'post_number':publication_number(rpc,contract,log),'facts':selected['facts'],
        'threshold':selected['threshold'],'proof_protocol':PROTOCOL,'disclosed_follower_count':disclosed,
        'valid_when_published':True,'accepted_at':accepted_at,'observed_at':observed,'credential_expiry':expiry,
        'credential_status':status,'publication_registry_hash':sha(canonical(legacy)),'public_id':None,'laboratory_only':True}
