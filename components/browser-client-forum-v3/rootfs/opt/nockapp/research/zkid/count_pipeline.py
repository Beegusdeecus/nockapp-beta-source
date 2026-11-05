"""Versioned count native/source integration; no installed v1 state is changed.

This module preserves exact authenticated counts through blind issuance. The
production remote service/wallet/schema migration remains a separate integration.
"""
from dataclasses import dataclass
import copy
import hashlib
import json
from pathlib import Path
import subprocess
from urllib.parse import urlencode

from count_policy import CountSession,SCHEME,POLICY_HASH,evaluate_count
from credential import private_child
from domain_pipeline import LabDomainIssuer,PendingHolder,definition_hash
from policy import SOURCE,ProviderClient,Rejected,canonical,digest,hex_string,identifier,require

PROFILE='nockapp-zkid-count-application-v2'
INTERNAL='nockapp-zkid-internal-count-v2'
BINARY=Path(__file__).resolve().parent/'local/count-native/debug/nockapp-zkid-count-v2'


class CountNative:
    def __init__(self,binary=BINARY):
        self.binary=Path(binary);self.sha256=hashlib.sha256(self.binary.read_bytes()).digest()

    def call(self,op,**body):
        require(hashlib.sha256(self.binary.read_bytes()).digest()==self.sha256,'count-binary-changed')
        data=canonical({'profile':INTERNAL,'call':{op:body}});require(len(data)<=262144,'count-input-size')
        try:
            result=subprocess.run([str(self.binary),'--internal-crypto'],input=data,capture_output=True,timeout=30,
                env={'PATH':'/usr/bin:/bin','LC_ALL':'C','RAYON_NUM_THREADS':'2'},preexec_fn=private_child)
            require(result.returncode==0 and not result.stderr and len(result.stdout)<=262144,'count-native-rejected')
            value=json.loads(result.stdout)
            require(type(value) is dict and set(value)=={'profile','result'} and value['profile']==INTERNAL
                and type(value['result']) is dict,'count-native-result')
            return value['result']
        except Rejected:raise
        except Exception:raise Rejected('count-native-unavailable') from None


@dataclass(repr=False)
class CountHeld:
    native: object
    private: dict
    local_zkid: object


class CountPending(PendingHolder):
    def receive(self,issued,public,session):
        require(type(session) is CountSession and session.request_scheme==SCHEME
            and session.desktop_nonce==self.desktop_nonce and session.commitment==self.request_digest
            and session.issuer_key==definition_hash(public),'count-request-substitution')
        attrs=issued['attributes']
        require(attrs['binding']==session.binding and attrs['source']==SOURCE and attrs['policy']==POLICY_HASH,'count-receipt-context')
        result=self.native.call('receive',pending=self.private,bundle=issued['bundle'],public=public,attributes=attrs)
        require(result['local_zkid']==self.local_zkid,'count-identity-substitution')
        return CountHeld(self.native,result['credential'],result['local_zkid']),result['ack']


class CountProvider(ProviderClient):
    def check(self,session,tweet_id,now):
        require(type(session) is CountSession,'count-session-version')
        session.check_time(now);identifier(tweet_id)
        tweets=self._get('/twitter/tweets?'+urlencode({'tweet_ids':tweet_id}))
        info=self._get('/twitter/user/info?'+urlencode({'userName':session.username}))
        return evaluate_count(session,tweet_id,tweets,info,now)


class LabCountIssuer(LabDomainIssuer):
    """Explicit lab coordinator; production must retain protected durable leases."""
    def begin(self,request,desktop_nonce,account_id,username,now):
        require(type(request) is dict and len(canonical(request))<=16384
            and request.get('blind_claim_labels')==['secret'],'count-blind-request')
        hex_string(desktop_nonce,64);self.validate_request(request)
        with self._lock:
            existing=self.find_begin(request,desktop_nonce,username,now)['session']
            if existing is not None:
                require(existing['account_id']==account_id,'source-account-mismatch')
                return CountSession(**existing)
            session=CountSession.create(desktop_nonce,digest(request),account_id,username,self.definition_hash,now)
            self._pending[session.binding]={'session':session,'request':copy.deepcopy(request),
                'old':self._accounts.get(account_id),'issued':False,'acknowledged':False,'aborted':False}
            self._persist()
            return session

    def stage_fixture(self,session,tweet_id,tweet_data,user_data,now):
        return self._stage(session,evaluate_count(session,tweet_id,tweet_data,user_data,now))

    def stage_provider(self,session,tweet_id,provider,now):
        require(isinstance(provider,CountProvider),'count-provider-required')
        return super().stage_provider(session,tweet_id,provider,now)

    def trust(self,challenge,now):
        return {'issuer':copy.deepcopy(self.public),'policy':POLICY_HASH,'challenge':copy.deepcopy(challenge),
            'current_sequence':self.sequence,'now':now}

    def status(self,session,nonce,now):
        result=super().status(session,nonce,now);result['profile']=PROFILE;return result
