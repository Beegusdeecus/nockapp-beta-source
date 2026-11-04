"""Canonical complete v5 bytes; optional opaque evidence is verified separately."""
import base64
import copy
import hashlib
from authorship import nonzero_hex
from authorship_v5 import validate_core,proof_shape,scopes
from policy import canonical,require,strict_json
PROFILE='nockapp-public-discussion-bundle-v5'
ENCODING='canonical-ascii-json-v1'
MAX_BYTES=65536
LIMITS={'wallet':4096,'followers':32768,'history':16384}

def blob(data,kind):
    require(kind in LIMITS and type(data) is bytes and 0<len(data)<=LIMITS[kind],'v5-evidence-size')
    return base64.b64encode(data).decode('ascii')

def unblob(value,kind):
    require(kind in LIMITS,'v5-evidence-kind')
    if value is None:return None
    require(type(value) is str and 0<len(value)<=4*((LIMITS[kind]+2)//3),'v5-evidence-size')
    try:raw=base64.b64decode(value,validate=True)
    except Exception:require(False,'v5-evidence-encoding')
    require(0<len(raw)<=LIMITS[kind] and base64.b64encode(raw).decode('ascii')==value,'v5-evidence-encoding')
    return raw

def evidence_hash(value,kind):return '0x'+hashlib.sha256(unblob(value,kind) or b'').hexdigest()

def validate_unsigned(u):
    require(type(u) is dict and set(u)=={'profile','encoding','core','author','evidence'} and u['profile']==PROFILE and u['encoding']==ENCODING,'v5-bundle-schema')
    validate_core(u['core']);a=u['author'];require(type(a) is dict and set(a)=={'exact','logical'},'v5-author-points')
    nonzero_hex(a['exact'],96);nonzero_hex(a['logical'],96)
    e=u['evidence'];require(type(e) is dict and set(e)==set(LIMITS),'v5-evidence-schema')
    for kind,value in e.items():unblob(value,kind)
    s=u['core']['selection'];require(s['address'] or e['wallet'] is None,'v5-unselected-wallet')
    require(s['followers_threshold'] is not None or e['followers'] is None,'v5-unselected-followers')
    require(len(canonical(u))<=MAX_BYTES,'v5-bundle-size');return u

def unsigned(core,points,*,wallet=None,followers=None,history=None):
    return validate_unsigned(copy.deepcopy({'profile':PROFILE,'encoding':ENCODING,'core':core,'author':points,
        'evidence':{'wallet':wallet,'followers':followers,'history':history}}))

def validate(v):
    require(type(v) is dict and set(v)=={'unsigned','authorship'},'v5-bundle-schema')
    u=validate_unsigned(v['unsigned']);proof_shape(v['authorship'],scopes(u['core']))
    require(len(canonical(v))<=MAX_BYTES,'v5-bundle-size');return v

def build(unsigned,proof):return validate(copy.deepcopy({'unsigned':unsigned,'authorship':proof}))
def encode(v):return canonical(validate(v))
def decode(data,expected_hash=None):
    require(type(data) is bytes and 0<len(data)<=MAX_BYTES,'v5-bundle-size')
    if expected_hash is not None:require('0x'+hashlib.sha256(data).hexdigest()==expected_hash,'v5-bundle-hash')
    v=validate(strict_json(data,max_bytes=MAX_BYTES));require(encode(v)==data,'v5-bundle-canonical');return v
