"""Independent scoped post verifier/controller, NOT issuer or wallet RPC.

New anonymous post facts: one joint proof, explicit fresh nonce consumption and
separate read-only archival checks. No hardware/production trust is inferred.
Installer owns audience/approved definition/backend/archive, never caller input.
"""
import copy
import hashlib
import os
from pathlib import Path
import secrets
import stat
import time

from domain_pipeline import LIMIT,PROFILE
from domain_authority import _challenge
from domain_state import PersistentDomainVerifier
from domain_post_authority import RECEIPT,validate_receipt
from policy import POLICY_HASH,canonical,digest,hex_string,require,strict_json,timestamp
from post_scope import PROFILE as REFERENCE,facts,scope

ARCHIVE='nockapp-zkid-post-proof-archive-v1'


def observation(proof):
    """Read ONLY after native verification of this exact proof.

    Upstream sequence maps are kept as lists; reject duplicate entries here too.
    No decoded claim alone establishes authenticity or an acceptance decision.
    """
    def pairs(value):
        require(type(value) is list and all(type(p) is list and len(p)==2 and type(p[0]) is str for p in value),
                'post-proof-shape')
        result=dict(value);require(len(result)==len(value),'post-proof-shape');return result
    disclosed=pairs(proof['proof']['disclosed_messages'])
    require(set(disclosed)=={'credential'},'post-proof-shape');claims=pairs(disclosed['credential'])
    def number(key):
        value=claims[key];require(type(value) is dict and set(value)=={'Number'}
            and type(value['Number']) is dict and set(value['Number'])=={'value'},'post-proof-shape')
        result=value['Number']['value'];timestamp(result);return result
    start,expiry=number('start'),number('expiry')
    require(start%3600==0 and expiry-start==86400,'post-proof-shape')
    return start,expiry


class PostProofArchive:
    """Immutable nonce-addressed public proofs, private application directory.

    No acceptance boolean, secret/wallet key, public ID or automatic reset. A
    durable archive precedes managed consumption; a missing archive fails closed.
    Managed receipt pins bytes; local file mutation cannot forge acceptance.
    """
    def __init__(self,directory):
        self.root=Path(directory)
        require(self.root.is_absolute() and '..' not in self.root.parts
                and not any(p.startswith('.env') for p in self.root.parts)
                and not any(p.is_symlink() for p in [self.root,*self.root.parents]),'post-archive')
        self.root.mkdir(parents=True,mode=0o700,exist_ok=True);info=self.root.stat()
        require(info.st_uid==os.getuid() and not info.st_mode&0o077,'post-archive')

    def _path(self,nonce):hex_string(nonce,64);return self.root/(nonce+'.json')

    def load(self,nonce):
        fd=os.open(self._path(nonce),os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o077
                    and info.st_nlink==1 and 0<info.st_size<=LIMIT,'post-archive')
            data=stream.read(LIMIT+1);value=strict_json(data,max_bytes=LIMIT)
        require(set(value)=={'profile','nonce','proof'} and value['profile']==ARCHIVE
                and value['nonce']==nonce and type(value['proof']) is dict and canonical(value)==data,'post-archive')
        return value['proof']

    def save(self,nonce,proof):
        target=self._path(nonce);body=canonical({'profile':ARCHIVE,'nonce':nonce,'proof':proof})
        require(len(body)<=LIMIT,'post-proof-size');stage=self.root/('.stage-'+secrets.token_hex(16))
        fd=os.open(stage,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            with os.fdopen(fd,'wb') as stream:stream.write(body);stream.flush();os.fsync(stream.fileno())
            try:os.link(stage,target)
            except FileExistsError:require(self.load(nonce)==proof,'post-proof-conflict')
        finally:stage.unlink()
        fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)


class _ReceiptConsumer:
    def __init__(self,backend,archive,proof,clock):
        self.backend,self.archive,self.proof,self.clock=backend,archive,proof,clock
    def public_view(self):return self.backend.public_view()
    def action_record(self,nonce):return self.backend.action_record(nonce)
    def consume_action(self,challenge):
        start,expiry=observation(self.proof)
        self.archive.save(challenge['nonce'],self.proof)
        now=self.clock();require(challenge['created_at']<=now<challenge['expires_at'],'action-expired')
        receipt={'profile':RECEIPT,'proof_sha256':digest(self.proof),'accepted_at':now,
                 'observed_at':start,'expires_at':expiry}
        self.backend.consume_post(challenge,receipt)


class PostVerifier:
    def __init__(self,backend,native,approved_definition,audience,archive,clock=None):
        hex_string(approved_definition,64);hex_string(audience,64)
        require(any(bytes.fromhex(audience)),'post-audience')
        self.backend,self.native,self.definition,self.audience,self.archive=backend,native,approved_definition,audience,archive
        self.clock=clock or (lambda:int(time.time()))

    def challenge(self,post,selected_facts):
        selected_facts=facts(selected_facts)
        return PersistentDomainVerifier(self.backend,self.native,self.definition).challenge(
            scope(post,self.audience),selected_facts,self.clock(),identity=False)

    def _context(self,post,selected_facts,nonce):
        selected_facts=facts(selected_facts);hex_string(nonce,64)
        row=self.backend.action_record(nonce);require(row is not None,'action-not-outstanding')
        challenge=strict_json(row[0]);require(_challenge(challenge)==row[0] and challenge['nonce']==nonce
            and challenge['profile']==PROFILE and challenge['identity'] is False
            and challenge['scope']==scope(post,self.audience) and challenge['facts']==selected_facts,'post-context')
        return challenge

    def accept(self,post,selected_facts,nonce,proof):
        proof=copy.deepcopy(proof);require(type(proof) is dict and len(canonical(proof))<=LIMIT,'post-proof-size')
        challenge=self._context(post,selected_facts,nonce);now=self.clock()
        consumer=_ReceiptConsumer(self.backend,self.archive,proof,self.clock)
        result=PersistentDomainVerifier(consumer,self.native,self.definition).verify(proof,challenge,now)
        require(result['public_id'] is None,'post-identity-disclosure')
        return {'profile':REFERENCE,'nonce':nonce,'facts':challenge['facts'],
                'laboratory':True,'verified':False,'fresh':True,'archival_only':False}

    def inspect(self,post,selected_facts,nonce):
        """NO fresh authorization/nonce consumption, even after a lost reply.

        Native verifier checks the original challenge at the managed acceptance
        time; independently enforce current source expiry + SAME current registry.
        A changed registry requires a fresh holder proof, never an old-root bypass.
        """
        started=time.monotonic();challenge=self._context(post,selected_facts,nonce)
        require(bool(self.backend.action_record(nonce)[1]),'post-not-accepted')
        receipt=self.backend.acceptance(nonce);require(receipt is not None,'post-not-accepted')
        validate_receipt(receipt,challenge);now=self.clock();timestamp(now)
        require(receipt['accepted_at']<=now<receipt['expires_at'],'post-expired')
        proof=self.archive.load(nonce);require(digest(proof)==receipt['proof_sha256'],'post-proof-changed')
        verifier=PersistentDomainVerifier(self.backend,self.native,self.definition);view=verifier._view()
        require(view['sequence']==challenge['registry_sequence'],'registry-state-changed')
        result=self.native.call('verify',public_input=proof,trust={'issuer':view['public'],'policy':POLICY_HASH,
            'challenge':challenge,'current_sequence':view['sequence'],'now':receipt['accepted_at']})
        require(result.get('accepted') is True,'domain-proof-rejected')
        require(observation(proof)==(receipt['observed_at'],receipt['expires_at']),'post-receipt')
        # Recheck after expensive verification to reject a concurrent revocation.
        require(self.backend.public_view()==view,'registry-state-changed')
        checked=self.clock();require(max(checked,now+time.monotonic()-started)<receipt['expires_at'],'post-expired')
        return {'profile':REFERENCE,'nonce':nonce,'facts':challenge['facts'],'observed_at':receipt['observed_at'],
                'expires_at':receipt['expires_at'],'checked_at':checked,
                'laboratory':True,'verified':False,'fresh':False,'archival_only':True}
