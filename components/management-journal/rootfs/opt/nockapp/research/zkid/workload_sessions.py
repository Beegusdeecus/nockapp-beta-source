"""Backend-only fixed-role IAM Roles Anywhere sessions and bounded renewal.

Identity keys enter as in-memory P-256 objects, never files/argv/environment.
No listener, generic signer, caller-selected role, credential chain, IMDS, proxy,
SDK retry or AWS resource creation. A measured supervisor must own this instance.
"""
import base64
import copy
from datetime import datetime,timezone
import hashlib
import http.client
import re
import socket
import ssl
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from policy import Rejected,canonical,hex_string,require,strict_json
from provisioning import validate_value

PROFILE='nockapp-zkid-workload-session-v1'
ALGORITHM='AWS4-X509-ECDSA-SHA256'
LIMIT=65536
UUID=r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'


def validate_config(value):
    require(type(value) is dict and set(value)=={'profile','region','account','purpose','namespace',
            'trust_anchor_arn','profile_arn','role_arn','certificate_sha256','duration_seconds'}
            and value['profile']==PROFILE and type(value['region']) is str
            and re.fullmatch(r'[a-z]{2}-[a-z]+-[1-9]',value['region'])
            and type(value['account']) is str and re.fullmatch(r'[0-9]{12}',value['account'])
            and type(value['purpose']) is str and value['purpose'] in ('issuer','budget','verifier','public-reader')
            and type(value['duration_seconds']) is int and 900<=value['duration_seconds']<=3600,'workload-config')
    for name in ('namespace','certificate_sha256'):
        hex_string(value[name],64);require(any(bytes.fromhex(value[name])),'workload-config')
    prefix='arn:aws:rolesanywhere:'+value['region']+':'+value['account']+':'
    for name,kind in [('trust_anchor_arn','trust-anchor'),('profile_arn','profile')]:
        require(type(value[name]) is str and re.fullmatch(re.escape(prefix+kind+'/')+UUID,value[name]),'workload-config')
    require(value['role_arn']=='arn:aws:iam::'+value['account']+':role/nockapp-zkid-'+value['purpose'],'workload-role')
    return value


class WorkloadSession:
    def __init__(self,config,certificate_der,private_key,context,dial=None):
        self.config=copy.deepcopy(validate_config(config))
        require(isinstance(context,ssl.SSLContext) and context.verify_mode==ssl.CERT_REQUIRED
                and context.check_hostname and context.minimum_version>=ssl.TLSVersion.TLSv1_2,'workload-tls')
        require(type(certificate_der) is bytes and 0<len(certificate_der)<=8192
                and hashlib.sha256(certificate_der).hexdigest()==self.config['certificate_sha256'],'workload-certificate')
        self._cert=x509.load_der_x509_certificate(certificate_der)
        require(self._cert.public_bytes(serialization.Encoding.DER)==certificate_der
                and isinstance(private_key,ec.EllipticCurvePrivateKey) and isinstance(private_key.curve,ec.SECP256R1)
                and self._cert.public_key()==private_key.public_key(),'workload-key')
        require(self._cert.version==x509.Version.v3 and self._cert.signature_hash_algorithm.name in ('sha256','sha384','sha512')
                and not self._cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                and self._cert.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature,'workload-certificate')
        cn=self._cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        ou=self._cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
        require(len(cn)==len(ou)==1 and cn[0].value=='nockapp-zkid-'+self.config['purpose']
                and ou[0].value==self.config['namespace'],'workload-subject')
        self._key=private_key;self._der=certificate_der;self._context=context
        self.host='rolesanywhere.'+self.config['region']+'.amazonaws.com'
        self._dial=dial or (lambda:socket.create_connection((self.host,443),timeout=10))

    def _request(self,now):
        require(self._cert.not_valid_before_utc.timestamp()<=now<self._cert.not_valid_after_utc.timestamp(),
                'workload-identity-expired')
        body=canonical({'durationSeconds':self.config['duration_seconds'],'profileArn':self.config['profile_arn'],
                        'roleArn':self.config['role_arn'],'trustAnchorArn':self.config['trust_anchor_arn']})
        date=datetime.fromtimestamp(now,timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        headers={'content-type':'application/json','host':self.host,'x-amz-date':date,
                 'x-amz-x509':base64.b64encode(self._der).decode('ascii')}
        signed=';'.join(sorted(headers));lines=''.join(k+':'+headers[k]+'\n' for k in sorted(headers))
        request='POST\n/sessions\n\n'+lines+'\n'+signed+'\n'+hashlib.sha256(body).hexdigest()
        scope=date[:8]+'/'+self.config['region']+'/rolesanywhere/aws4_request'
        text=ALGORITHM+'\n'+date+'\n'+scope+'\n'+hashlib.sha256(request.encode('ascii')).hexdigest()
        signature=self._key.sign(text.encode('ascii'),ec.ECDSA(hashes.SHA256())).hex()
        headers['authorization']=(ALGORITHM+' Credential='+str(self._cert.serial_number)+'/'+scope+
                                  ', SignedHeaders='+signed+', Signature='+signature)
        return body,headers

    def _parse(self,data,now):
        value=strict_json(data,max_bytes=LIMIT)
        require(type(value) is dict and set(value)=={'credentialSet','subjectArn'}
                and type(value['credentialSet']) is list and len(value['credentialSet'])==1,'workload-session-response')
        prefix='arn:aws:rolesanywhere:'+self.config['region']+':'+self.config['account']+':subject/'
        require(type(value['subjectArn']) is str and re.fullmatch(re.escape(prefix)+UUID,value['subjectArn']),'workload-session-response')
        entry=value['credentialSet'][0]
        require(type(entry) is dict and set(entry)=={'assumedRoleUser','credentials','packedPolicySize','roleArn','sourceIdentity'}
                and entry['roleArn']==self.config['role_arn'] and entry['sourceIdentity']=='nockapp-zkid-'+self.config['purpose']
                and type(entry['packedPolicySize']) is int and 0<=entry['packedPolicySize']<=100,'workload-session-response')
        role=entry['assumedRoleUser'];prefix='arn:aws:sts::'+self.config['account']+':assumed-role/nockapp-zkid-'+self.config['purpose']+'/'
        require(type(role) is dict and set(role)=={'arn','assumedRoleId'} and type(role['arn']) is str
                and re.fullmatch(re.escape(prefix)+r'[A-Za-z0-9+=,.@_-]{2,64}',role['arn'])
                and type(role['assumedRoleId']) is str and re.fullmatch(r'[A-Z0-9]{16,128}:'+re.escape(role['arn'].split('/')[-1]),role['assumedRoleId']),
                'workload-session-response')
        creds=entry['credentials'];require(type(creds) is dict and set(creds)=={'accessKeyId','secretAccessKey','sessionToken','expiration'}
                and type(creds['expiration']) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z',creds['expiration']),
                'workload-session-response')
        try:expires=int(datetime.fromisoformat(creds['expiration'].replace('Z','+00:00')).timestamp())
        except (ValueError,OverflowError):raise Rejected('workload-session-response') from None
        require(now+600<=expires<=now+self.config['duration_seconds']+5,'workload-session-response')
        return copy.deepcopy(validate_value('managed-writer-credentials',{'access_key_id':creds['accessKeyId'],
            'secret_access_key':creds['secretAccessKey'],'session_token':creds['sessionToken'],'expires_at':expires}))

    def create_session(self):
        raw=secure=connection=timer=None
        try:
            body,headers=self._request(int(time.time()))
            raw=self._dial();raw.settimeout(10)
            def expire():
                try:(secure or raw).shutdown(socket.SHUT_RDWR)
                except OSError:pass
            timer=threading.Timer(15,expire);timer.daemon=True;timer.start()
            secure=self._context.wrap_socket(raw,server_hostname=self.host)
            connection=http.client.HTTPConnection(self.host,timeout=10);connection.sock=secure;connection.set_debuglevel(0)
            connection.request('POST','/sessions',body=body,headers={**headers,'Connection':'close','Accept-Encoding':'identity'})
            response=connection.getresponse()
            if response.status!=201:
                raise Rejected('workload-session-unavailable' if response.status==429 or 500<=response.status<600
                               else 'workload-authorization-rejected')
            for name in ('Content-Length','Transfer-Encoding','Content-Type','Content-Encoding'):
                require(sum(k.lower()==name.lower() for k,_ in response.getheaders())<=1,'workload-session-response')
            length=response.getheader('Content-Length');transfer=response.getheader('Transfer-Encoding','')
            require(not(length and transfer) and transfer.lower() in ('','chunked')
                    and response.getheader('Content-Encoding','identity').lower()=='identity'
                    and response.getheader('Content-Type','').split(';')[0].lower()=='application/json'
                    and (length is None or re.fullmatch(r'[0-9]{1,9}',length) and int(length)<=LIMIT),'workload-session-response')
            data=response.read(LIMIT+1)
            require(len(data)<=LIMIT and (length is None or len(data)==int(length)),'workload-session-response')
            return self._parse(data,int(time.time()))
        except Rejected:raise
        except Exception:raise Rejected('workload-session-unavailable') from None
        finally:
            if timer:timer.cancel()
            if connection:connection.close()
            elif secure:secure.close()
            elif raw:raw.close()


class WorkloadCredentials:
    """One refresh at a time; refresh cannot retry the enclosing AWS operation."""
    def __init__(self,session):
        require(isinstance(session,WorkloadSession),'workload-session-source')
        self._session=session;self._lock=threading.RLock();self._cached=None
        self._deadline=0;self._retry_at=0;self._last_utc=0;self._fatal=False

    def get(self):
        with self._lock:
            now=int(time.time());mono=time.monotonic()
            require(not self._fatal and now>=self._last_utc-5,'workload-credentials-unavailable')
            self._last_utc=max(now,self._last_utc)
            remaining=min(self._deadline-mono,self._cached['expires_at']-now) if self._cached else 0
            if remaining>300:return copy.deepcopy(self._cached)
            if mono>=self._retry_at:
                try:
                    value=self._session.create_session();after=int(time.time());end=time.monotonic()
                    validate_value('managed-writer-credentials',value)
                    require(after>=now-5 and value['expires_at']>after+600,'workload-session-response')
                    if self._cached:require(value['expires_at']>self._cached['expires_at'],'workload-session-response')
                    self._cached=copy.deepcopy(value);self._deadline=end+value['expires_at']-after
                    self._retry_at=0;return copy.deepcopy(value)
                except Exception as error:
                    self._retry_at=time.monotonic()+30
                    if not isinstance(error,Rejected) or error.args!=('workload-session-unavailable',):
                        self._fatal=True;self._cached=None
                        raise Rejected('workload-credentials-unavailable') from None
            now=int(time.time());mono=time.monotonic()
            require(self._cached is not None and min(self._deadline-mono,self._cached['expires_at']-now)>5,
                    'workload-credentials-unavailable')
            return copy.deepcopy(self._cached)
