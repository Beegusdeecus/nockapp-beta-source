"""Selected old author points AND this new core/author in one common-key proof.

The resolver supplies original bytes/time only AFTER public chain inclusion is
checked. We reconstruct and verify original author proofs, never a remote verdict.
No recursive history/badge verification is needed to establish original authorship.
"""
from authorship import scopes as old_scopes
from authorship_v5 import reference,scopes,proof_shape,verify as verify_author
from policy import canonical,digest,require,strict_json
from public_bundle_v5 import blob,unblob,decode
PROFILE='nockapp-attached-historical-authorship-v5'
MAX_OLD=15  # Pinned generic worker permits 16 statements including the NEW post.

def original(ref,new_core,resolve,native):
    reference(ref,historical=True);x=new_core['context']
    require(ref['chain_id']==x['chain_id'],'v5-history-chain')
    data,indexed_at=resolve(ref)
    if ref['protocol']==5:
        v=decode(data,ref['bundle_hash']);u=v['unsigned'];c=u['core']
        require(verify_author(native,u,v['authorship']),'v5-history-original-author')
        point=u['author']['exact'];scope=scopes(c)[0]
    else:
        # Legacy v4 authored posts remain eligible; unbound v1-v3 do not.
        from base_protocol import sha
        from authorship import intent
        require(type(data) is bytes and len(data)<=32768 and sha(data)==ref['bundle_hash'],'v5-history-original-hash')
        v=strict_json(data,max_bytes=32768)
        require(set(v)=={'profile','encoding','context','post','selection','authorship','evidence','address_disclosure'}
            and v['profile']=='nockapp-public-discussion-bundle-v4' and v['encoding']=='canonical-ascii-json-v1'
            and canonical(v)==data,'v5-history-original-schema')
        c=intent(v['post'],v['context'],disclose_address=v['selection']['address'],followers_threshold=v['selection']['followers_threshold'])
        require(native.verify_post(c,v['authorship']),'v5-history-original-author')
        point=v['authorship']['statements'][0]['pseudonym'];scope=old_scopes(c)[0]
    old=c['context'];require(old['application']==x['application'] and old['chain_id']==ref['chain_id']
        and old['contract']==ref['contract'] and old['protocol']==ref['protocol'],'v5-history-original-context')
    require(c['post']['created_at']<=indexed_at,'v5-history-original-time')
    return scope,point,indexed_at

def material(core,points,records,resolve,native):
    require(type(records) is list and 1<=len(records)<=MAX_OLD,'v5-history-selection')
    for r in records:reference(r,historical=True)
    require(len({digest(r) for r in records})==len(records),'v5-history-selection')
    prior=[original(r,core,resolve,native) for r in records]
    ss=[scopes(core)[0]]+[p[0] for p in prior]
    require(len({digest(s) for s in ss})==len(ss),'v5-history-selection')
    ctx=digest({'profile':PROFILE,'new_core_sha256':digest(core),'new_author':points['exact'],'records':records})
    return ss,[points['exact']]+[p[1] for p in prior],ctx,[p[2] for p in prior]

def prove(native,secret,core,points,records,resolve):
    ss,expected,ctx,_=material(core,points,records,resolve,native)
    p=native.call('prove',secret=secret,scopes=ss,context=ctx)['proof'];proof_shape(p,ss)
    require([v['pseudonym'] for v in p['statements']]==expected,'v5-history-key-mismatch')
    require(native.call('verify',proof=p,scopes=ss,context=ctx)=={'accepted':True},'v5-history-proof')
    return blob(canonical({'profile':PROFILE,'records':records,'proof':p}),'history')

def verify(native,u,indexed_at,resolve):
    v=strict_json(unblob(u['evidence']['history'],'history'),max_bytes=16384)
    require(set(v)=={'profile','records','proof'} and v['profile']==PROFILE,'v5-history-schema')
    ss,expected,ctx,times=material(u['core'],u['author'],v['records'],resolve,native)
    require(all(t<=indexed_at for t in times),'v5-history-future-record')
    proof_shape(v['proof'],ss);require([p['pseudonym'] for p in v['proof']['statements']]==expected,'v5-history-key-mismatch')
    require(native.call('verify',proof=v['proof'],scopes=ss,context=ctx)=={'accepted':True},'v5-history-proof')
    return v['records']
