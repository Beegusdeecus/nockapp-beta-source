"""Bounded private-pipe adapter for the distinct hidden-date v3 worker."""
import hashlib
from pathlib import Path
import subprocess
from credential import private_child
from policy import canonical,require,strict_json,Rejected
INTERNAL='nockapp-renewal-internal-v3'
BINARY=Path(__file__).resolve().parent/'local/renewal-native/debug/nockapp-renewal-count-v3'

class RenewalNative:
    def __init__(self,binary=BINARY):
        self.binary=Path(binary);self.sha256=hashlib.sha256(self.binary.read_bytes()).hexdigest()

    def call(self,op,**body):
        require(hashlib.sha256(self.binary.read_bytes()).hexdigest()==self.sha256,'renewal-binary-changed')
        data=canonical({'profile':INTERNAL,'call':{op:body}});require(len(data)<=262144,'renewal-input-size')
        try:
            p=subprocess.run([str(self.binary),'--internal-renewal'],input=data,capture_output=True,timeout=45,
                env={'PATH':'/usr/bin:/bin','LC_ALL':'C','RAYON_NUM_THREADS':'2'},preexec_fn=private_child)
            require(p.returncode==0 and not p.stderr and len(p.stdout)<=262144,'renewal-native-rejected')
            v=strict_json(p.stdout,max_bytes=262144)
            require(type(v) is dict and set(v)=={'profile','result'} and v['profile']==INTERNAL and type(v['result']) is dict,'renewal-native-result')
            return v['result']
        except Rejected:raise
        except Exception:raise Rejected('renewal-native-unavailable') from None

def public_view(native,original):
    from domain_pipeline import definition_hash
    require(type(original) is dict and set(original)=={'public','definition_hash','sequence'}
        and original['definition_hash']==definition_hash(original['public']) and type(original['sequence']) is int
        and 0<=original['sequence']<2**53,'renewal-issuer-view')
    result=native.call('public-view',public=original['public'])['public']
    require({k:v for k,v in result.items() if k!='schema'}=={k:v for k,v in original['public'].items() if k!='schema'},'renewal-key-continuity')
    return {'public':result,'definition_hash':definition_hash(result),'sequence':original['sequence']}
