"""Independent application post scope, separate from legacy passport scopes."""
import hashlib
import json
import re
from policy import canonical,digest,hex_string,require,timestamp

PROFILE='nockapp-zkid-post-reference-v1'
SCOPE='NOCKAPP/ZKID/POST-SCOPE/v1'
FACTS={'account-controlled','followers-at-least-10000'}
# ECMAScript String.trim (Python strip differs for NEL and BOM).
TRIM='\u0009\u000a\u000b\u000c\u000d\u0020\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff'


def text(value,limit,*,empty=False):
    require(type(value) is str and (empty or bool(value)),'post-schema')
    try:value.encode('utf-8')
    except UnicodeError:require(False,'post-schema')
    require(len(value.encode('utf-16-le'))//2<=limit,'post-schema')
    return value


def uuid(value):
    require(type(value) is str and re.fullmatch(
        r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',value),'post-schema')
    return value


def facts(value):
    require(type(value) is list and 1<=len(value)<=2 and all(type(v) is str and v in FACTS for v in value)
            and len(set(value))==len(value),'post-facts')
    return sorted(value)


def payload(post):
    require(type(post) is dict and set(post)=={'kind','id','created_at','thread_id','title','body','references','claims'},'post-schema')
    require(post['kind'] in ('thread','comment'),'post-schema');uuid(post['id']);timestamp(post['created_at'])
    body=text(post['body'],6000);require(body==body.strip(TRIM),'post-schema')
    if post['kind']=='thread':
        title=text(post['title'],120);require(title==title.strip(TRIM) and post['thread_id'] is None,'post-schema')
    # Existing discussions have opaque legacy thread IDs. Bind those exact IDs
    # without migrating them; only the NEW signed post's own identity is UUIDv4.
    else:text(post['thread_id'],128);require(post['title'] is None,'post-schema')
    require(type(post['references']) is list and len(post['references'])<=64,'post-schema')
    for ref in post['references']:
        require(type(ref) is list and len(ref)==2,'post-schema');text(ref[0],2048)
        require(ref[1] is None or type(ref[1]) is str and re.fullmatch(r'[1-9][0-9]{0,19}',ref[1]),'post-schema')
    require(type(post['claims']) is list and len(post['claims'])<=4,'post-schema')
    seen=set()
    for claim in post['claims']:
        require(type(claim) is list and len(claim)==2 and type(claim[0]) is str and claim[0] in
                {'x-account','followers-1k','followers-10k','followed-by'} and claim[0] not in seen,'post-schema')
        seen.add(claim[0]);require(claim[1] is None or type(claim[1]) is str,'post-schema')
        if claim[1] is not None:text(claim[1],64)
    # This exact ordered UTF-8 JSON array is reproducible by JSON.stringify.
    return json.dumps([SCOPE,*[post[k] for k in ('kind','id','created_at','thread_id','title','body','references','claims')]],
                      ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8')


def scope(post,audience):
    hex_string(audience,64);require(any(bytes.fromhex(audience)),'post-audience')
    return digest({'profile':PROFILE,'audience':audience,'post_sha256':hashlib.sha256(payload(post)).hexdigest()})
