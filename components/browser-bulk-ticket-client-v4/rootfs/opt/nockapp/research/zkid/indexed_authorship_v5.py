"""Independent v5 public verifier: mandatory author, independent silent badges.

Caller authenticates index inclusion and issuer snapshots using public chain data.
This module performs no remote-verdict, private-key, credential or issuer-DB call.
"""
from authorship_v5 import verify as verify_author,logical_key
from policy import require,timestamp
from public_bundle_v5 import decode
import wallet_authorship_v5 as wallet
import count_authorship_v5 as followers
import historical_authorship_v5 as history

def verify_indexed_bundle(data,bundle_hash,where,indexed_at,now,native,*,count_native=None,
        issuer_view=None,current_issuer_view=None,resolve_history=None):
    value=decode(data,bundle_hash);u=value['unsigned'];c=u['core'];x=c['context']
    require(type(where) is dict and set(where)=={'protocol','chain_id','application','contract'}
        and all(x[k]==where[k] for k in where),'v5-index-context')
    timestamp(indexed_at);timestamp(now);require(c['post']['created_at']<=indexed_at<=now,'v5-index-time')
    require(native is not None and verify_author(native,u,value['authorship']),'v5-author-rejected')
    result={'post':c['post'],'thread':c['thread'],'references':c['references'],'authorship_checked':True,
        'logical_key':logical_key(u),'display':{'address':None,'followers':None,'history':None},
        'historical_follower_evidence':None}
    # Neither optional branch gates another or changes any committed bytes.
    if c['selection']['address']:
        try:result['display']['address']=wallet.verify(u,indexed_at)
        except Exception:pass
    if c['selection']['followers_threshold'] is not None:
        try:
            require(count_native is not None and issuer_view is not None,'v5-issuer-unavailable')
            checked=followers.verify(native,count_native,u,issuer_view,indexed_at,now,current_issuer_view)
            result['historical_follower_evidence']={k:checked[k] for k in ('valid_when_indexed','threshold','observed_at','expires_at')}
            if checked['eligible_now']:result['display']['followers']={k:checked[k] for k in ('threshold','observed_at','expires_at')}
        except Exception:pass
    if u['evidence']['history'] is not None:
        try:
            require(resolve_history is not None,'v5-history-unavailable')
            result['display']['history']=history.verify(native,u,indexed_at,resolve_history)
        except Exception:pass
    return result
