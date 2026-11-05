"""Source-evaluated composite credential path; explicitly LABORATORY ONLY.

Internal native calls run in private pipes, never a public signing endpoint.
The issuer never receives the holder scalar, processed credential or public ID.
No network, credentials, browser profile or desktop keyring is accessed here.
"""
from dataclasses import dataclass
import copy
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import threading

from credential import private_child
from policy import (SOURCE, POLICY_HASH, Session, Rejected, canonical, digest, evaluate,
                    require, timestamp, hex_string, identifier, DISCOVERY_INTERVAL, DISCOVERY_ATTEMPTS)

PROFILE = 'nockapp-zkid-domain-application-lab-v1'
INTERNAL = 'nockapp-zkid-internal-credx-v1'
BINARY = Path(__file__).resolve().parent/'domain-crypto/target/debug/nockapp-zkid-domain-research'
LIMIT = 262144


class Native:
    """Local research executable; production needs independently approved packaging."""
    def __init__(self, binary=BINARY):
        self.binary = Path(binary)
        self.sha256 = hashlib.sha256(self.binary.read_bytes()).digest()

    def call(self, op, **body):
        require(hashlib.sha256(self.binary.read_bytes()).digest() == self.sha256, 'domain-binary-changed')
        data = canonical({'profile':INTERNAL, 'call':{op:body}})
        require(len(data) <= LIMIT, 'domain-input-size')
        try:
            result = subprocess.run([str(self.binary),'--internal-crypto'],input=data,capture_output=True,
                timeout=15,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','RAYON_NUM_THREADS':'2'},preexec_fn=private_child)
            require(result.returncode == 0 and not result.stderr and len(result.stdout) <= LIMIT,'domain-native-rejected')
            value = json.loads(result.stdout)
            require(type(value) is dict and set(value) == {'profile','result'} and value['profile'] == INTERNAL
                    and type(value['result']) is dict,'domain-native-result')
            return value['result']
        except Rejected: raise
        except Exception: raise Rejected('domain-native-unavailable') from None


def definition_hash(public):
    return digest({k:v for k,v in public.items() if k != 'revocation_registry'})


def attributes(values, binding):
    return {'source':values[1],'policy':values[2],'start':int(values[3]),'expiry':int(values[4]),
            'controlled':int(values[5]),'followers':int(values[6]),'binding':binding}


@dataclass(repr=False)
class PendingHolder:
    native: object
    private: dict
    request: dict
    desktop_nonce: str
    local_zkid: object

    @classmethod
    def create(cls, native, public):
        result = native.call('prepare',public=public)
        return cls(native,result['pending'],result['request'],secrets.token_hex(32),result['local_zkid'])

    @property
    def request_digest(self): return digest(self.request)

    def receive(self, issued, public, session):
        require(session.desktop_nonce == self.desktop_nonce and session.commitment == self.request_digest
                and session.issuer_key == definition_hash(public),'domain-request-substitution')
        attrs = issued['attributes']
        require(attrs['binding'] == session.binding and attrs['source'] == SOURCE and attrs['policy'] == POLICY_HASH,
                'domain-receipt-context')
        result = self.native.call('receive',pending=self.private,bundle=issued['bundle'],public=public,attributes=attrs)
        require(result['local_zkid'] == self.local_zkid,'domain-identity-substitution')
        return HeldCredential(self.native,result['credential'],result['local_zkid']),result['ack']


@dataclass(repr=False)
class HeldCredential:
    native: object
    private: dict
    local_zkid: object

    def present(self, issuer, challenge):
        with issuer._lock:
            require(challenge['registry_sequence'] == issuer.sequence,'registry-state-changed')
            handle = self.private['credential']['claims'][0]['Revocation']['value']
            # Only the already issuer-known revocation handle crosses to the
            # issuer. The secret-bearing credential stays in the holder process.
            refreshed = issuer.native.call('witness',issuer=issuer._issuer,handle=handle)
            current = self.native.call('refresh',credential=self.private,public=refreshed['public'],witness=refreshed['witness'])
            trust = issuer.trust(challenge,challenge['created_at'])
        self.private = current['credential']
        return self.native.call('present',credential=self.private,trust=trust)


class LabDomainIssuer:
    """Trusted in-memory lab coordinator, prepared for a persistence callback.

    Only stage_fixture accepts supplied response bytes. A measured production
    controller must call the fixed ProviderClient INSIDE its trust boundary.
    """
    def __init__(self, native, now, capacity=100):
        result = native.call('setup',capacity=capacity)
        self.native = native
        self._issuer = result['issuer']; self.public = result['public']; self._handles = result['handles']
        self.definition_hash = definition_hash(self.public)
        self._next = 0; self.sequence = timestamp(now)
        self._accounts = {}; self._pending = {}; self._actions = {}
        self._lock = threading.RLock(); self._persist_callback = None

    def _persist(self):
        if self._persist_callback is not None: self._persist_callback()

    def find_begin(self, request, desktop_nonce, username, now):
        """Recover exact persisted begin before another paid profile lookup."""
        hex_string(desktop_nonce,64)
        with self._lock:
            matches=[p for p in self._pending.values() if p['request']==request
                     and p['session'].desktop_nonce==desktop_nonce and p['session'].username==username]
            require(len(matches)<=1,'registration-unavailable')
            if not matches:return {'session':None}
            pending=matches[0];session=pending['session'];session.check_time(now)
            require(not pending.get('aborted',False),'registration-unavailable')
            return {'session':session.__dict__}

    def begin(self, request, desktop_nonce, account_id, username, now):
        require(type(request) is dict and len(canonical(request)) <= 16384
                and request.get('blind_claim_labels') == ['secret'],'domain-blind-request')
        self.validate_request(request)
        with self._lock:
            existing=self.find_begin(request,desktop_nonce,username,now)['session']
            if existing is not None:
                require(existing['account_id']==account_id,'source-account-mismatch')
                return Session(**existing)
            session = Session.create(desktop_nonce,digest(request),account_id,username,self.definition_hash,now,
                                     request_scheme='credx-bbs-domain-0.2.1')
            self._pending[session.binding] = {'session':session,'request':copy.deepcopy(request),
                'old':self._accounts.get(account_id),'issued':False,'acknowledged':False,'aborted':False}
            self._persist()
        return session

    def stage_fixture(self, session, tweet_id, tweet_data, user_data, now):
        values = evaluate(session,tweet_id,tweet_data,user_data,now)
        return self._stage(session,values)

    def validate_request(self, request):
        result=self.native.call('validate-request',issuer=self._issuer,request=request)
        require(result.get('valid') is True,'domain-blind-request')
        return {'valid':True}

    def stage_provider(self, session, tweet_id, provider, now):
        # provider is a measured-controller-owned object, never a message field.
        # It authenticates fixed-host TLS and invokes the same source evaluator.
        with self._lock:
            self._pending_session(session)
            require(not self._pending[session.binding]['issued']
                    and 'handle' not in self._pending[session.binding],'issuance-replay')
        return self._stage(session,provider.check(session,tweet_id,now))

    def _discovery(self, session):
        pending=self._pending_session(session)
        require(not pending['issued'] and 'handle' not in pending,'registration-unavailable')
        value=pending.get('discovery',{'attempts':0,'next_poll_at':session.created_at,
                                       'failed':False,'in_flight':False,'tweet_id':None})
        require(type(value) is dict and set(value)=={'attempts','next_poll_at','failed','in_flight','tweet_id'}
                and type(value['attempts']) is int and 0<=value['attempts']<=DISCOVERY_ATTEMPTS
                and type(value['next_poll_at']) is int
                and session.created_at<=value['next_poll_at']<=session.created_at+600+DISCOVERY_INTERVAL
                and type(value['failed']) is bool and type(value['in_flight']) is bool,'discovery-state')
        if value['tweet_id'] is not None:identifier(value['tweet_id'])
        return pending,value

    def reserve_discovery(self, session, now):
        session.check_time(now)
        with self._lock:
            pending,value=self._discovery(session)
            require(not value['failed'],'discovery-failed')
            require(not value['in_flight'],'discovery-recovery-required')
            result={**copy.deepcopy(value),'admitted':False}
            if value['tweet_id'] is not None or now<value['next_poll_at']:return result
            require(value['attempts']<DISCOVERY_ATTEMPTS,'discovery-limit')
            value={**value,'attempts':value['attempts']+1,'next_poll_at':now+DISCOVERY_INTERVAL,'in_flight':True}
            pending['discovery']=value
            self._persist()  # CAS succeeds BEFORE any paid timeline request.
            return {**copy.deepcopy(value),'admitted':True}

    def finish_discovery(self, session, attempt, tweet_id, now):
        session.check_time(now)
        if tweet_id is not None:identifier(tweet_id)
        with self._lock:
            pending,value=self._discovery(session)
            require(type(attempt) is int and value['attempts']==attempt and attempt>0
                    and not value['failed'] and value['in_flight'] is True
                    and value['tweet_id'] is None,'discovery-state')
            pending['discovery']={**value,'tweet_id':tweet_id,'in_flight':False};self._persist()
            return {**copy.deepcopy(pending['discovery']),'admitted':False}

    def fail_discovery(self, session, attempt):
        with self._lock:
            pending,value=self._discovery(session)
            require(type(attempt) is int and value['attempts']==attempt and attempt>0
                    and value['in_flight'] is True and value['tweet_id'] is None,'discovery-state')
            pending['discovery']={**value,'failed':True,'in_flight':False};self._persist()
            return {'failed':True}

    def _pending_session(self, session):
        pending=self._pending.get(session.binding)
        require(pending is not None and pending['session']==session and not pending.get('aborted',False),
                'registration-not-pending')
        return pending

    def _stage(self, session, values):
        with self._lock:
            pending = self._pending_session(session)
            require(not pending['issued']
                    and 'handle' not in pending,'issuance-replay')
            require(self._next < len(self._handles),'registry-capacity')
            pending['handle'] = self._handles[self._next]; self._next += 1
            pending['base_sequence'] = self.sequence
            self._persist()  # Burn/reserve BEFORE the native signature operation.
            attrs = attributes(values,session.binding)
            result = self.native.call('stage',issuer=self._issuer,request=pending['request'],
                                      handle=pending['handle'],attributes=attrs)
            pending['issued'] = True; pending['attributes'] = attrs
            pending['response'] = {'bundle':result['bundle'],'attributes':copy.deepcopy(attrs)}
            self._persist()  # Persist before returning any signed credential.
            return copy.deepcopy(pending['response'])

    def recover_delivery(self, session, now):
        """Resume the SAME response, without issuing or querying the provider.

        The full session includes privately exchanged random nonces; the public
        X post contains only its digest. A digest alone is not a recovery token.
        Production carries this inside the same authenticated encrypted channel.
        """
        session.check_time(now)
        with self._lock:
            pending = self._pending.get(session.binding)
            require(pending and pending['session'] == session and pending['issued']
                    and not pending['acknowledged'] and not pending.get('aborted',False)
                    and 'response' in pending,'registration-delivery-unavailable')
            return copy.deepcopy(pending['response'])

    def status(self, session, nonce, now):
        hex_string(nonce,64);timestamp(now)
        require(now>=session.created_at,'session-expired')
        with self._lock:
            pending=self._pending.get(session.binding)
            require(pending and pending['session']==session,'registration-not-found')
            state=('committed' if pending['acknowledged'] else 'aborted' if pending.get('aborted',False)
                   else 'expired' if now>session.created_at+600 else 'issued' if pending['issued']
                   else 'failed' if 'handle' in pending else 'pending')
            return {'profile':PROFILE,'binding':session.binding,'state':state,'nonce':nonce,'observed_at':now,
                    'registry_sequence':self.sequence,'laboratory':True,'verified':False}

    def abort(self, session, nonce, now):
        hex_string(nonce,64);timestamp(now)
        require(now>=session.created_at,'session-expired')
        with self._lock:
            pending=self._pending.get(session.binding)
            require(pending and pending['session']==session and not pending['acknowledged'],
                    'registration-already-committed')
            if not pending.get('aborted',False):
                pending['aborted']=True;pending.pop('response',None);self._persist()
            return self.status(session,nonce,now)

    def commit(self, session, ack, now):
        session.check_time(now)
        with self._lock:
            pending = self._pending.get(session.binding)
            require(pending is not None and pending['issued'] and not pending['acknowledged']
                    and not pending.get('aborted',False),'replacement-not-pending')
            require(self._accounts.get(session.account_id) == pending['old'],'replacement-raced')
            require(pending['base_sequence'] == self.sequence,'registry-state-changed')
            result = self.native.call('commit',issuer=self._issuer,handle=pending['handle'],old_handle=pending['old'],
                                      ack=ack,attributes=pending['attributes'])
            self._issuer = result['issuer']; self.public = result['public']; self.sequence += 1
            self._accounts[session.account_id] = pending['handle']; pending['acknowledged'] = True
            pending.pop('response',None)
            self._persist()  # Persist activation/revocation BEFORE acknowledging.
            return {'profile':PROFILE,'laboratory':True,'verified':False,'registry_sequence':self.sequence,
                    'replaced':pending['old'] is not None}

    def trust(self, challenge, now):
        return {'issuer':copy.deepcopy(self.public),'policy':POLICY_HASH,'challenge':copy.deepcopy(challenge),
                'current_sequence':self.sequence,'now':now}


class LabDomainVerifier:
    def __init__(self, issuer):
        self.issuer = issuer; self.definition_hash = issuer.definition_hash
        self._actions = issuer._actions; self._lock = issuer._lock

    def challenge(self, scope, facts, now, *, identity=False):
        hex_string(scope,64); timestamp(now)
        require(type(identity) is bool and type(facts) is list and 1 <= len(facts) <= 2
                and all(type(f) is str for f in facts) and len(set(facts)) == len(facts)
                and set(facts) <= {'account-controlled','followers-at-least-10000'},'presentation-facts')
        with self.issuer._lock:
            body = {'profile':PROFILE,'nonce':secrets.token_hex(32),'scope':scope,'facts':sorted(facts),'identity':identity,
                'registry_sequence':self.issuer.sequence,'created_at':now,'expires_at':now+60}
        with self._lock:
            self._actions[body['nonce']] = {'body':canonical(body).decode('ascii'),'used':False}
            self.issuer._persist()
        return body

    def verify(self, proof, challenge, now):
        with self._lock, self.issuer._lock:
            record = self._actions.get(challenge['nonce'])
            require(record and record['body'] == canonical(challenge).decode('ascii') and not record['used'],'action-not-outstanding')
            require(challenge['created_at'] <= now < challenge['expires_at'],'action-expired')
            require(self.issuer.sequence == challenge['registry_sequence'],'registry-state-changed')
            require(definition_hash(self.issuer.public) == self.definition_hash,'domain-issuer-changed')
            result = self.issuer.native.call('verify',public_input=proof,trust=self.issuer.trust(challenge,now))
            require(result.get('accepted') is True,'domain-proof-rejected')
            record['used'] = True
            self.issuer._persist()
            return {'profile':PROFILE,'laboratory':True,'verified':False,'hardware_verified':False,
                    'cryptographic_proof_valid':True,'public_id_bound':challenge['identity'],'facts':challenge['facts'],
                    'public_id':copy.deepcopy(proof['claimed_id']) if challenge['identity'] else None}
