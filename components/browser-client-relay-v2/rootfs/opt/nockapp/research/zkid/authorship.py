"""Protocol4 private authorship component. Not yet a publication/credential gate.

One holder scalar controls locally created signing identity, per-intent public
pseudonyms, and selective common-controller proofs. No Twitter credential needed.
Native key generation/proving is private-pipe only, never a server operation.
"""
import copy
import hashlib
from pathlib import Path
import subprocess

from credential import private_child
from policy import canonical,digest,hex_string,require,strict_json,timestamp
from post_scope import payload

PROFILE='nockapp-private-authorship-v4'
INTERNAL='nockapp-authorship-internal-v4'
INTENT='nockapp-authored-post-intent-v4'
OWNERSHIP='nockapp-signing-ownership-challenge-v4'
CLAIM='nockapp-selected-authorship-challenge-v4'
BINARY=Path(__file__).resolve().parent/'local/authorship-native/debug/nockapp-authorship-v4'
MAX_SELECTED=16


def nonzero_hex(value,size):
    hex_string(value,size)
    require(value==value.lower() and any(bytes.fromhex(value)),'authorship-hex')
    return value


def context(value):
    require(type(value) is dict and set(value)=={'protocol','chain_id','application','contract','submission_id'}
        and type(value['protocol']) is int and value['protocol']==4
        and type(value['chain_id']) is int and value['chain_id'] in (31337,84532),'authorship-context')
    for key,size in (('application',64),('contract',40)):
        v=value[key];require(type(v) is str and v.startswith('0x'),'authorship-context');nonzero_hex(v[2:],size)
    nonzero_hex(value['submission_id'],64)
    return value


def intent(post,where,*,disclose_address=False,followers_threshold=None):
    require(type(disclose_address) is bool,'authorship-selection')
    require(followers_threshold is None or (type(followers_threshold) is int and 0<=followers_threshold<2**53),'authorship-selection')
    require(len(payload(post))<=8192 and post['claims']==[],'authorship-post')
    context(where)
    return copy.deepcopy({'profile':INTENT,'context':where,'post':post,
        'disclosures':{'address':disclose_address,'followers_threshold':followers_threshold}})


def validate_intent(value):
    require(type(value) is dict and set(value)=={'profile','context','post','disclosures'}
        and value['profile']==INTENT and type(value['disclosures']) is dict
        and set(value['disclosures'])=={'address','followers_threshold'},'authorship-intent')
    require(value==intent(value['post'],value['context'],disclose_address=value['disclosures']['address'],
        followers_threshold=value['disclosures']['followers_threshold']),'authorship-intent')
    return value


def post_scope(value):
    return {'kind':'post','intent_sha256':digest(validate_intent(value))}


def scopes(value):
    # Wallet disclosure signs this post-scoped author directly. It must not
    # additionally publish a global holder key that could link other wallets.
    return [post_scope(value)]


def post_context(value):
    return digest({'profile':PROFILE,'purpose':'authorize-exact-post','intent_sha256':digest(validate_intent(value))})


def ownership_challenge(nonce,request_sha256,audience,created_at,expires_at):
    nonzero_hex(nonce,64);nonzero_hex(request_sha256,64);nonzero_hex(audience,64)
    timestamp(created_at);timestamp(expires_at)
    require(expires_at-created_at==60,'authorship-challenge-window')
    return {'profile':OWNERSHIP,'purpose':'bind-local-signing-identity-to-blind-request','nonce':nonce,
        'request_sha256':request_sha256,'audience':audience,'created_at':created_at,'expires_at':expires_at}


def selected_challenge(intents,nonce,audience,created_at,expires_at,*,disclose_address=False):
    require(type(intents) is list and 1<=len(intents)<=MAX_SELECTED and type(disclose_address) is bool,'authorship-selected')
    selected=[digest(validate_intent(v)) for v in intents]
    require(len(set(selected))==len(selected),'authorship-selected-duplicate')
    nonzero_hex(nonce,64);nonzero_hex(audience,64);timestamp(created_at);timestamp(expires_at)
    require(expires_at-created_at==60,'authorship-challenge-window')
    return {'profile':CLAIM,'purpose':'prove-selected-post-authorization','intent_sha256':selected,
        'nonce':nonce,'audience':audience,'created_at':created_at,'expires_at':expires_at,'disclose_address':disclose_address}


class AuthorshipNative:
    def __init__(self,binary=BINARY):
        self.binary=Path(binary);self.sha256=hashlib.sha256(self.binary.read_bytes()).hexdigest()

    def call(self,operation,**body):
        require(hashlib.sha256(self.binary.read_bytes()).hexdigest()==self.sha256,'authorship-binary-changed')
        data=canonical({'profile':INTERNAL,'call':{operation:body}});require(len(data)<=65536,'authorship-input-size')
        try:
            done=subprocess.run([str(self.binary),'--internal-authorship'],input=data,capture_output=True,
                timeout=15,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},preexec_fn=private_child)
        except (OSError,subprocess.TimeoutExpired):
            require(False,'authorship-native-unavailable')
        require(done.returncode==0 and not done.stderr and len(done.stdout)<=65536,'authorship-native-rejected')
        result=strict_json(done.stdout,max_bytes=65536)
        require(set(result)=={'profile','result'} and result['profile']==INTERNAL and type(result['result']) is dict,'authorship-native-response')
        return result['result']

    def authorize(self,secret,value):
        return self.call('prove',secret=secret,scopes=scopes(value),context=post_context(value))['proof']

    def verify_post(self,value,proof):
        # Both disclosures off still requires the private authorization proof.
        return self.call('verify',proof=proof,scopes=scopes(value),context=post_context(value))=={'accepted':True}

    def claim(self,secret,intents,challenge):
        selected=self._selected(intents,challenge)
        return self.call('prove',secret=secret,scopes=selected,context=digest(challenge))['proof']

    @staticmethod
    def _selected(intents,challenge):
        require(type(challenge) is dict and set(challenge)=={'profile','purpose','intent_sha256','nonce','audience',
            'created_at','expires_at','disclose_address'},'authorship-selected-challenge')
        expected=selected_challenge(intents,challenge['nonce'],challenge['audience'],challenge['created_at'],
            challenge['expires_at'],disclose_address=challenge['disclose_address'])
        require(challenge==expected,'authorship-selected-challenge')
        # Address disclosure is a separate wallet signature over this selected
        # proof; it does not require publishing the holder's permanent G1 key.
        return [post_scope(v) for v in intents]

    def verify_claim(self,intents,post_proofs,challenge,proof,now):
        selected=self._selected(intents,challenge);timestamp(now)
        require(challenge['created_at']<=now<challenge['expires_at'],'authorship-claim-expired')
        require(type(post_proofs) is list and len(post_proofs)==len(intents),'authorship-selected')
        require(all(self.verify_post(v,p) for v,p in zip(intents,post_proofs)),'authorship-original-proof')
        if self.call('verify',proof=proof,scopes=selected,context=digest(challenge))!={'accepted':True}:return False
        # A new valid equality proof under another key is insufficient: it must
        # open exactly the pseudonyms committed in the selected original posts.
        return all(old['statements'][0]['pseudonym']==new['pseudonym']
            for old,new in zip(post_proofs,proof['statements']))
