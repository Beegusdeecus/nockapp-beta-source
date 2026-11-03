"""Helper-owned public-post workflow over fresh attested issuer TLS.

Installer supplies trust/directory and loopback OR public endpoint, never browser messages. No
arbitrary network/signing/decrypt interface, browser sessions or final-ID input.
Secrets, receipts and local activation/action proofs remain on the desktop.
"""
import copy
import re
import secrets
import socket
import time
from urllib.parse import urlsplit

from domain_desktop import DomainDesktop
from domain_pipeline import definition_hash,PROFILE
from domain_transport import request,validate_endpoint,connect_endpoint
from domain_trust import validate_approval
from policy import Rejected,Session,identifier,require,DISCOVERY_INTERVAL


def post_id(value,username):
    require(type(value) is str and 0<len(value)<=512,'account-or-post-id')
    if value.isascii() and value.isdigit():return identifier(value)
    parsed=urlsplit(value)
    require(parsed.scheme=='https' and parsed.netloc in ('x.com','www.x.com','twitter.com','www.twitter.com'),
            'account-or-post-id')
    match=re.fullmatch(r'/([A-Za-z0-9_]{1,15})/status/([1-9][0-9]{0,19})/?',parsed.path)
    require(match is not None and match[1].lower()==username.lower(),'account-or-post-id')
    # Extract an ID only; this URL is NEVER fetched, saved or sent to the issuer.
    return identifier(match[2])


class DomainBridge:
    session_type=Session
    credential_profile=PROFILE

    def __init__(self,directory,approved,port=None,*,endpoint=None):
        approved=copy.deepcopy(approved);validate_approval(approved)
        if endpoint is None:require(type(port) is int and 1<=port<=65535,'issuer-loopback-port')
        else:
            require(port is None,'issuer-endpoint')
            endpoint=copy.deepcopy(validate_endpoint(endpoint))
        self._endpoint=endpoint
        self._approved=approved;self._port=port;self.desktop=DomainDesktop(directory)

    def _remote(self,operation,body):
        raw=(connect_endpoint(self._endpoint) if self._endpoint is not None else
             socket.create_connection(('127.0.0.1',self._port),timeout=10))
        response=request(raw,
                         operation,body,self._approved)
        require(response['status']=='ok',response.get('code','issuer-operation-failed'))
        return response['result']

    def _pending(self):
        value=self.desktop._check(self.desktop.wallet.load('pending'))
        self._check_definition(value)
        return value

    def _check_definition(self,value):
        require(value['definition_hash']==self._approved['definition_hash'],'issuer-not-approved')

    def _view(self):
        view=self._remote('registry',{})
        require(type(view) is dict and set(view)=={'definition_hash','public','sequence'}
                and type(view['public']) is dict and type(view['sequence']) is int and view['sequence']>=0
                and definition_hash(view['public'])==view['definition_hash']==self._approved['definition_hash'],
                'issuer-registry')
        return view

    def _display(self,pending,state):
        result={'state':state,'credential_saved':self.desktop.wallet.read('credential.sealed',missing=True) is not None,
                'laboratory':True,'verified':False}
        if pending is not None:
            result['username']=pending['username']
            if pending['session'] is not None:
                session=self.session_type(**pending['session'])
                result.update(post_text=session.post_text,expires_at=session.created_at+600)
        return result

    def local_status(self):
        with self.desktop.transaction():
            if self.desktop.wallet.read('pending.sealed',missing=True) is None:
                # Validate/decrypt any active record before reporting saved state.
                if self.desktop.wallet.read('credential.sealed',missing=True) is not None:
                    record=self.desktop._check(self.desktop.wallet.load('credential'))
                    self._check_definition(record)
                    return self._display(None,'credential-saved')
                return self._display(None,'empty')
            value=self._pending()
            return self._display(value,'receipt-saved' if value['credential'] is not None else
                                 'awaiting-post' if value['session'] is not None else 'begin-recovery-required')

    def _prepare_holder(self,public,account_id,username):
        return self.desktop.prepare(public,account_id,username)

    def begin(self,username,approve_public_profile_lookup):
        require(approve_public_profile_lookup is True,'consent-required')
        require(type(username) is str and re.fullmatch(r'[A-Za-z0-9_]{1,15}',username),'account-handle')
        with self.desktop.transaction():
            if self.desktop.wallet.read('pending.sealed',missing=True) is None:
                view=self._view()
                self._prepare_holder(view['public'],None,username)
            value=self._pending();require(value['username']==username,'registration-already-pending')
            if value['session'] is None:
                public=self.desktop.resume_request()
                begun=self._remote('begin',{**public,'username':username,'approve_public_profile_lookup':True})
                require(type(begun) is dict and set(begun)=={'session','post_text','expires_at'},'registration-context')
                session=self.session_type(**begun['session']);session.check_time(int(time.time()))
                require(begun['post_text']==session.post_text and begun['expires_at']==session.created_at+600,
                        'registration-context')
                # Stable ID is learned ONLY here, from authenticated source-bound
                # issuer state. Browser never supplies it or the session object.
                self.desktop.record_session(session);value=self._pending()
            return self._display(value,'receipt-saved' if value['credential'] is not None else 'awaiting-post')

    def _status(self,value,operation='status'):
        require(value['session'] is not None,'registration-context')
        session=self.session_type(**value['session']);nonce=secrets.token_hex(32);now=int(time.time())
        status=self._remote(operation,{'session':session.__dict__,'nonce':nonce})
        require(type(status) is dict and set(status)=={'profile','binding','state','nonce','observed_at',
                'registry_sequence','laboratory','verified'} and status['profile']==self.credential_profile
                and status['binding']==session.binding and status['nonce']==nonce
                and type(status['observed_at']) is int and now-5<=status['observed_at']<=int(time.time())+5
                and type(status['registry_sequence']) is int and status['registry_sequence']>=0
                and status['state'] in ('pending','issued','committed','aborted','expired','failed')
                and status['laboratory'] is True and status['verified'] is False,'registration-status')
        return status,nonce

    def _witness(self,view,*,pending=False):
        handle=self.desktop.witness_handle(pending=pending)
        witness=self._remote('witness',{'handle':handle})
        require(type(witness) is dict and set(witness)=={'witness','public','sequence','definition_hash'}
                and witness['definition_hash']==view['definition_hash'] and witness['sequence']==view['sequence']
                and witness['public']==view['public'],'registry-state-changed')
        return witness

    def _finish(self,value,status):
        if status['state']=='issued':
            if value['credential'] is None:
                issued=self._remote('recover-delivery',{'session':value['session']})
                self.desktop.receive(issued,value['public_definition']);value=self._pending()
            ack=self.desktop.recover_ack()  # Already encrypted BEFORE any commit.
            self._remote('commit',{'session':value['session'],'ack':ack})
        elif status['state']!='committed':return self._display(value,status['state'])
        require(value['credential'] is not None,'registration-recovery-required')
        view=self._view();witness=self._witness(view,pending=True)
        self.desktop.promote(view,witness,int(time.time()))
        # Local activation proof never crosses the issuer connection.
        return self._display(None,'credential-saved')

    def check_post(self,value,approve_source_check):
        require(approve_source_check is True,'consent-required')
        with self.desktop.transaction():
            pending=self._pending();require(pending['session'] is not None,'registration-context')
            tweet=post_id(value,pending['username'])
            if pending['credential'] is None:
                issued=self._remote('check-post',{'session':pending['session'],'tweet_id':tweet,'approve_source_check':True})
                self.desktop.receive(issued,pending['public_definition']);pending=self._pending()
            status,_=self._status(pending)
            return self._finish(pending,status)

    def poll_registration(self,approve_source_check):
        """One consented poll; schedule hints are public, session/receipt stay local.

        Discovery returns only a candidate. The original separately attested
        check/receipt/commit/promotion path still authorizes the credential.
        Transport/source uncertainty is raised, never retried here.
        """
        require(approve_source_check is True,'consent-required')
        with self.desktop.transaction():
            if self.desktop.wallet.read('pending.sealed',missing=True) is None:
                return self.local_status()
            pending=self._pending()
            require(pending['session'] is not None,'registration-begin-recovery-required')
            if pending['credential'] is not None:return self.recover()
            session=self.session_type(**pending['session'])
            found=self._remote('discover-post',{'session':session.__dict__,'approve_source_check':True})
            require(type(found) is dict and set(found)=={'state','tweet_id','next_poll_at','expires_at'}
                    and found['state'] in ('waiting','found','issued','committed')
                    and type(found['expires_at']) is int and found['expires_at']==session.created_at+600,
                    'registration-discovery-result')
            if found['state'] in ('issued','committed'):
                require(found['tweet_id'] is None and found['next_poll_at'] is None,'registration-discovery-result')
                return self.recover()
            require(type(found['next_poll_at']) is int and session.created_at<=found['next_poll_at']
                    <=found['expires_at']+DISCOVERY_INTERVAL,'registration-discovery-result')
            if found['state']=='found':
                return self.check_post(identifier(found['tweet_id']),True)
            require(found['tweet_id'] is None,'registration-discovery-result')
            return {**self._display(pending,'awaiting-post'),'next_check_at':found['next_poll_at']}

    def recover(self):
        with self.desktop.transaction():
            value=self._pending()
            if value['session'] is None:
                raise Rejected('registration-begin-recovery-required')
            status,_=self._status(value)
            return self._finish(value,status)

    def cancel(self):
        with self.desktop.transaction():
            value=self._pending()
            if value['session'] is None:self.desktop.cancel_before_receipt()
            else:
                status,nonce=self._status(value,'abort')
                self.desktop.confirm_remote_abort(status,nonce,int(time.time()))
            return self._display(None,'cancelled')

    def forget(self):
        with self.desktop.transaction():return self.desktop.forget_credential()

    def present(self,challenge):
        with self.desktop.transaction():
            view=self._view();witness=self._witness(view)
            # Scope/challenge/proof/public ID NEVER go to the issuer. Only its
            # public registry and the issuer-known opaque handle are requested.
            return self.desktop.present(view,witness,challenge,int(time.time()))
