"""One explicit STS identity read for a fixed new-host setup role/session.

No ambient chain, IMDS, retries, role assumption or IAM change. Identity is not
proof of narrow policies; those require administrator review and live evidence.
GetCallerIdentity wire schema: AWS STS APIReference/API_GetCallerIdentity.html.
"""
import re
import socket
import time
from urllib.parse import urlencode
import xml.etree.ElementTree as ET
from aws_transport import _silence_sdk
from policy import require,Rejected
from provisioning import validate_value
from setup_aws_sdk import activate
from ticket_aws_credentials_v1 import tls_context,check_tls,http,xml_children,text,XML

ROLES=('payment','publication','refund')
def session_name(role,nonce):
    require(role in ROLES and type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce),'ticket-setup-session')
    return 'nockapp-setup-'+role+'-'+nonce

def identity(credentials,region,account,role,nonce,*,context=None,dial=None):
    name=session_name(role,nonce)
    require(type(account) is str and re.fullmatch('[0-9]{12}',account)
        and type(region) is str and re.fullmatch('[a-z]{2}-[a-z]+-[1-9]',region),'ticket-setup-identity-scope')
    credentials=validate_value('managed-writer-credentials',credentials)
    require(credentials['expires_at']>=int(time.time())+300,'ticket-setup-identity-expiry')
    try:
        context=tls_context() if context is None else context;check_tls(context)
        host='sts.'+region+'.amazonaws.com'
        activate()
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
        from botocore.credentials import Credentials
        _silence_sdk()
        body=urlencode({'Action':'GetCallerIdentity','Version':'2011-06-15'}).encode('ascii')
        request=AWSRequest(method='POST',url='https://'+host+'/',data=body,
            headers={'Content-Type':'application/x-www-form-urlencoded; charset=utf-8'})
        auth=Credentials(credentials['access_key_id'],credentials['secret_access_key'],credentials['session_token'])
        SigV4Auth(auth,'sts',region).add_auth(request)
        raw,content=http(host,'POST','/',dict(request.headers.items()),body,
            dial=dial or (lambda:socket.create_connection((host,443),timeout=5)),context=context,limit=16384)
        require(content in ('text/xml','application/xml'),'ticket-setup-identity-response')
        xml=raw.decode('utf-8');require('<!' not in xml,'ticket-setup-identity-response')
        root=ET.fromstring(xml)
        require(root.tag=='{'+XML+'}GetCallerIdentityResponse','ticket-setup-identity-response')
        fields=xml_children(root,{'GetCallerIdentityResult','ResponseMetadata'})
        value=xml_children(fields['GetCallerIdentityResult'],{'Account','Arn','UserId'})
        role_arn='arn:aws:iam::'+account+':role/nockapp-ticket-setup-'+role
        arn='arn:aws:sts::'+account+':assumed-role/nockapp-ticket-setup-'+role+'/'+name
        require(text(value['Account'])==account and text(value['Arn'])==arn
            and re.fullmatch('[A-Z0-9]{16,128}:'+re.escape(name),text(value['UserId'])),'ticket-setup-identity-mismatch')
        return {'account_id':account,'role_arn':role_arn,'session_arn':arn}
    except Exception:raise Rejected('ticket-setup-identity-unavailable') from None
