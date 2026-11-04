"""Fresh recipient-bound, explicitly linked selected-history proofs.

Only public challenge/proof files persist here. No holder identity/root, key,
credential, issuer witness or unrelated history is exported. Current API has no
wallet endorsement: per-post address disclosure is independent and unchanged.
"""
import copy
import secrets
from authorship import selected_challenge,nonzero_hex,PROFILE as PROOF_PROFILE,CLAIM
from policy import canonical,digest,require,timestamp

REQUEST='nockapp-selected-authorship-request-v4'
RESPONSE='nockapp-selected-authorship-response-v4'
RECEIPT='nockapp-selected-authorship-verification-v4'
REQUESTS='nockapp-selected-authorship-requests-v4'
RESPONSES='nockapp-selected-authorship-responses-v4'


def numbers(value):
    require(type(value) is list and 1<=len(value)<=16 and all(type(n) is int and 0<n<2**53 for n in value)
        and len(set(value))==len(value),'authored-history-selection')


def validate_request(value,scope):
    require(type(value) is dict and set(value)=={'profile','scope','numbers','bundle_hashes','challenge'}
        and value['profile']==REQUEST and canonical(value['scope'])==canonical(scope),'authored-history-request')
    numbers(value['numbers']);hashes=value['bundle_hashes'];c=value['challenge']
    require(type(hashes) is list and len(hashes)==len(value['numbers']),'authored-history-request')
    for h in hashes:
        require(type(h) is str and h.startswith('0x'),'authored-history-request');nonzero_hex(h[2:],64)
    require(type(c) is dict and set(c)=={'profile','purpose','intent_sha256','nonce','audience','created_at','expires_at','disclose_address'}
        and c['profile']==CLAIM and c['purpose']=='prove-selected-post-authorization' and c['disclose_address'] is False,
        'authored-history-request')
    nonzero_hex(c['nonce'],64);nonzero_hex(c['audience'],64);timestamp(c['created_at']);timestamp(c['expires_at'])
    require(c['expires_at']-c['created_at']==60 and type(c['intent_sha256']) is list
        and len(c['intent_sha256'])==len(hashes),'authored-history-request')
    for h in c['intent_sha256']:nonzero_hex(h,64)
    require(len(set(c['intent_sha256']))==len(hashes),'authored-history-request')
    require(len(canonical(value))<=16384,'authored-history-request')
    return value


def validate_response(value,scope):
    require(type(value) is dict and set(value)=={'profile','request_sha256','request','proof'}
        and value['profile']==RESPONSE and value['request_sha256']==digest(validate_request(value['request'],scope)),
        'authored-history-response')
    p=value['proof'];require(type(p) is dict and set(p)=={'profile','statements','response'} and p['profile']==PROOF_PROFILE
        and type(p['statements']) is list and len(p['statements'])==len(value['request']['numbers']),'authored-history-response')
    nonzero_hex(p['response'],64)
    for item,h in zip(p['statements'],value['request']['challenge']['intent_sha256']):
        require(type(item) is dict and set(item)=={'scope','pseudonym','nonce_commitment'}
            and item['scope']=={'kind':'post','intent_sha256':h},'authored-history-response')
        nonzero_hex(item['pseudonym'],96);nonzero_hex(item['nonce_commitment'],96)
    require(len(canonical(value))<=32768,'authored-history-response')
    return value


class AuthoredHistoryDesktop:
    def __init__(self,desktop):
        from authored_bundle_desktop import AuthoredBundleDesktop
        require(isinstance(desktop,AuthoredBundleDesktop),'authored-history-config')
        self.desktop=desktop
        self.scope={k:desktop.identity[k] for k in ('protocol','chain_id','application','contract','registry')}
        self.scope['issuer_definition']=desktop.identity['definition_hash']
    def now(self):return int(self.desktop.clock())
    def _requests(self):
        data=self.desktop._read('authorship-requests.json',missing=True)
        if data is None:return {'profile':REQUESTS,'scope':copy.deepcopy(self.scope),'entries':[]}
        require(type(data) is dict and set(data)=={'profile','scope','entries'} and data['profile']==REQUESTS
            and data['scope']==self.scope and type(data['entries']) is list and len(data['entries'])<=100,'authored-history-record')
        seen=set()
        for row in data['entries']:
            require(type(row) is dict and set(row)=={'request','request_sha256','response_sha256','receipt'}
                and row['request_sha256']==digest(validate_request(row['request'],self.scope)) and row['request_sha256'] not in seen,
                'authored-history-record');seen.add(row['request_sha256'])
            if row['response_sha256'] is None:require(row['receipt'] is None,'authored-history-record')
            else:
                nonzero_hex(row['response_sha256'],64);r=row['receipt']
                require(type(r) is dict and set(r)=={'profile','request_sha256','challenge_checked_at'} and r['profile']==RECEIPT
                    and r['request_sha256']==row['request_sha256'],'authored-history-record')
                timestamp(r['challenge_checked_at']);c=row['request']['challenge']
                require(c['created_at']<=r['challenge_checked_at']<c['expires_at'],'authored-history-record')
        return data
    def _responses(self):
        data=self.desktop._read('authorship-responses.json',missing=True)
        if data is None:return {'profile':RESPONSES,'scope':copy.deepcopy(self.scope),'entries':[]}
        require(type(data) is dict and set(data)=={'profile','scope','entries'} and data['profile']==RESPONSES and data['scope']==self.scope
            and type(data['entries']) is list and len(data['entries'])<=100,'authored-history-record')
        seen=set()
        for value in data['entries']:
            validate_response(value,self.scope);h=value['request_sha256'];require(h not in seen,'authored-history-record');seen.add(h)
        return data
    def _material(self,request):
        value=self.desktop._reader_instance().history_material(request['numbers'])
        require(value['scope']==self.scope and value['bundle_hashes']==request['bundle_hashes'],'authored-history-selection-mismatch')
        c=request['challenge'];expected=selected_challenge(value['intents'],c['nonce'],c['audience'],c['created_at'],c['expires_at'])
        require(c==expected,'authored-history-selection-mismatch')
        return value
    def request(self,selected,approve_request):
        require(approve_request is True,'consent-required');numbers(selected)
        with self.desktop.lock():
            box=self._requests();require(len(box['entries'])<100,'authored-history-storage-limit')
            value=self.desktop._reader_instance().history_material(selected);now=self.now()
            c=selected_challenge(value['intents'],secrets.token_hex(32),secrets.token_hex(32),now,now+60)
            result={'profile':REQUEST,'scope':copy.deepcopy(self.scope),'numbers':list(selected),'bundle_hashes':value['bundle_hashes'],'challenge':c}
            validate_request(result,self.scope);h=digest(result)
            box['entries'].append({'request':copy.deepcopy(result),'request_sha256':h,'response_sha256':None,'receipt':None})
            self.desktop._write('authorship-requests.json',box)
            require(self._requests()['entries'][-1]['request']==result,'authored-history-durable-copy')
            return result
    def requests(self,after,limit):
        require(type(after) is int and 0<=after<=100 and type(limit) is int and 1<=limit<=8,'authored-history-page')
        with self.desktop.lock():
            all_rows=self._requests()['entries'];rows=all_rows[after:after+limit]
            return {'profile':REQUESTS,'entries':[{'request':copy.deepcopy(r['request']),'request_sha256':r['request_sha256'],
                'challenge_checked_at':None if r['receipt'] is None else r['receipt']['challenge_checked_at']} for r in rows],
                'next_after':after+len(rows),'more':after+len(rows)<len(all_rows)}
    def prove(self,request,approve_linking):
        require(approve_linking is True,'consent-required');validate_request(request,self.scope)
        with self.desktop.lock():
            box=self._responses();h=digest(request);old=next((v for v in box['entries'] if v['request_sha256']==h),None)
            if old is not None:return copy.deepcopy(old)  # Exact lost-reply export, no fresh presence claim.
            require(len(box['entries'])<100,'authored-history-storage-limit')
            value=self._material(request);now=self.now();c=request['challenge']
            require(c['created_at']<=now<c['expires_at'],'authorship-claim-expired')
            result=self.desktop.author.prove_selected(value['intents'],value['post_proofs'],c,now,True)
            response={'profile':RESPONSE,'request_sha256':h,'request':copy.deepcopy(request),'proof':result['proof']}
            validate_response(response,self.scope)
            require(c['created_at']<=self.now()<c['expires_at'],'authorship-claim-expired')
            box['entries'].append(response);self.desktop._write('authorship-responses.json',box)
            require(self._responses()['entries'][-1]==response,'authored-history-durable-copy')
            return copy.deepcopy(response)
    def verify(self,response,request_sha256):
        nonzero_hex(request_sha256,64);validate_response(response,self.scope)
        require(response['request_sha256']==request_sha256,'authored-history-request-mismatch')
        with self.desktop.lock():
            box=self._requests();row=next((r for r in box['entries'] if r['request_sha256']==request_sha256),None)
            require(row is not None and row['request']==response['request'],'authored-history-recipient-mismatch')
            h=digest(response);old=row['receipt'];c=row['request']['challenge']
            if old is not None:require(row['response_sha256']==h,'authored-history-response-conflict')
            when=self.now() if old is None else old['challenge_checked_at']
            result=self.desktop._reader_instance().verify_selected_claim(row['request']['numbers'],c,response['proof'],when,
                expected_nonce=c['nonce'],expected_audience=c['audience'])
            checked_at=self.now()
            if old is None:
                require(c['created_at']<=checked_at<c['expires_at'],'authorship-claim-expired')
                row['response_sha256']=h;row['receipt']={'profile':RECEIPT,'request_sha256':request_sha256,'challenge_checked_at':checked_at}
                self.desktop._write('authorship-requests.json',box)
            return {'profile':RECEIPT,'request_sha256':request_sha256,**result,'checked_at':checked_at,
                'challenge_checked_at':row['receipt']['challenge_checked_at'],'current_possession_checked':old is None,'recovered':old is not None}
