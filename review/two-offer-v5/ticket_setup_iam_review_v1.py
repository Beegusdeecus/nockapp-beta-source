"""Public-only setup IAM proposal; never reads credentials or calls AWS.

The caller independently pins the public review/keyset and reviews the result.
No apply path, live resource discovery, certificate signing, deployment/funding,
or claim that policy generation establishes effective AWS permissions.
"""
import base64
import copy
from datetime import datetime,timezone
import re
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec,rsa
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID,ExtensionOID
from policy import canonical,digest,require
import ticket_key_setup_v1 as setup
from ticket_setup_identity_v1 import session_name
from ticket_setup_session_v1 import REVIEW,APPROVAL
from ticket_new_keys_v1 import PUBLIC

PROFILE='nockapp-ticket-setup-iam-review-v1'
ACCOUNT='419720240831'
REGION='ap-southeast-2'
OPERATOR='arn:aws:iam::'+ACCOUNT+':user/nockapp-operator'
ROLE_PREFIX='arn:aws:iam::'+ACCOUNT+':role/nockapp-ticket-setup-'
ORIGINAL_KMS='arn:aws:kms:'+REGION+':'+ACCOUNT+':key/f5bc0a85-c760-4c79-b2a1-fc70e83d9d82'
ORIGINAL_CA='51034b0fbe78ab88659ace315c10462876ef4a6f98c32365bcbdd662c115d91d'
DOCUMENTATION={
    'context':'https://docs.aws.amazon.com/kms/latest/developerguide/conditions-kms.html',
    'identity':'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html',
    'boundary':'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html',
    'duration':'https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html'}

def der_public(key):
    return key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)

def decode(value):
    require(type(value) is str and 0<len(value)<=12000,'ticket-iam-public-encoding')
    raw=base64.b64decode(value,validate=True)
    require(base64.b64encode(raw).decode()==value,'ticket-iam-public-encoding')
    return raw

def usage(extensions,hostname):
    required={ExtensionOID.BASIC_CONSTRAINTS,ExtensionOID.KEY_USAGE,
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME,ExtensionOID.EXTENDED_KEY_USAGE}
    allowed=required|{ExtensionOID.SUBJECT_KEY_IDENTIFIER,ExtensionOID.AUTHORITY_KEY_IDENTIFIER}
    require(required<=set(e.oid for e in extensions)<=allowed,'ticket-iam-tls-extensions')
    bc=extensions.get_extension_for_class(x509.BasicConstraints)
    ku=extensions.get_extension_for_class(x509.KeyUsage)
    require(bc.critical and bc.value==x509.BasicConstraints(False,None)
        and ku.critical and ku.value.public_bytes()==x509.KeyUsage(True,False,False,False,False,False,False,None,None).public_bytes()
        and list(extensions.get_extension_for_class(x509.SubjectAlternativeName).value)==[x509.DNSName(hostname)]
        and list(extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)==[ExtendedKeyUsageOID.SERVER_AUTH],
        'ticket-iam-tls-usage')

def admit(review,expected,public,public_pin,now):
    require(type(review) is dict and set(review)=={'profile','session_id','request_sha256','public_keys_sha256',
        'plan','plan_sha256','certificates','approval'} and digest(review)==expected
        and review['profile']==REVIEW and review['approval']==APPROVAL,'ticket-iam-review')
    require(type(review['session_id']) is str and re.fullmatch('[a-f0-9]{32}',review['session_id'])
        and type(review['request_sha256']) is str and re.fullmatch('[a-f0-9]{64}',review['request_sha256']),
        'ticket-iam-review-binding')
    require(type(public) is dict and set(public)=={'profile','ticket_spki','key_bindings','tls'}
        and public['profile']==PUBLIC and digest(public)==public_pin==review['public_keys_sha256']
        and type(public['tls']) is dict and set(public['tls'])==set(setup.ROLES),'ticket-iam-public-binding')
    ticket_raw=decode(public['ticket_spki']);ticket=serialization.load_der_public_key(ticket_raw)
    require(isinstance(ticket,rsa.RSAPublicKey) and ticket.key_size==3072
        and ticket.public_numbers().e==65537 and der_public(ticket)==ticket_raw,'ticket-iam-ticket-key')
    require(type(public['key_bindings']) is dict and set(public['key_bindings'])=={'publication','refund'}
        and len(set(public['key_bindings'].values()))==2,'ticket-iam-service-keys')
    setup.validate_public(review['plan'],review['plan_sha256'])
    require(type(review['certificates']) is dict and set(review['certificates'])==set(setup.ROLES),
        'ticket-iam-certificates')
    leaves=[]
    for role in setup.ROLES:
        value=review['plan']['roles'][role];cfg=value['backend'];tls=public['tls'][role]
        require(cfg['records']['account_id']==ACCOUNT and cfg['records']['region']==REGION
            and value['kms_key_arn']!=ORIGINAL_KMS and cfg['tls']['root_sha256']!=ORIGINAL_CA,
            'ticket-iam-original-or-foreign-scope')
        require(type(tls) is dict and set(tls)=={'hostname','key_sha256','csr_der'}
            and cfg['tls']['hostname']==tls['hostname'] and cfg['tls']['key_sha256']==tls['key_sha256']
            and cfg['key_bindings']==public['key_bindings']
            and cfg['offer']['terms']['ticket_spki']==public['ticket_spki'],'ticket-iam-generated-bindings')
        raw=decode(tls['csr_der']);csr=x509.load_der_x509_csr(raw)
        key=csr.public_key();subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,tls['hostname'])])
        require(csr.public_bytes(serialization.Encoding.DER)==raw and csr.is_signature_valid
            and csr.signature_hash_algorithm.name=='sha256' and csr.subject==subject
            and isinstance(key,ec.EllipticCurvePublicKey) and isinstance(key.curve,ec.SECP256R1)
            and setup.storage.sha(der_public(key))==tls['key_sha256'],'ticket-iam-csr')
        usage(csr.extensions,tls['hostname'])
        raw=decode(review['certificates'][role]);leaf=x509.load_der_x509_certificate(raw)
        root=x509.load_der_x509_certificate(decode(cfg['tls']['root_certificate_der']))
        require(leaf.public_bytes(serialization.Encoding.DER)==raw and leaf.version==x509.Version.v3
            and leaf.subject==subject and der_public(leaf.public_key())==der_public(key)
            and leaf.signature_hash_algorithm.name in ('sha256','sha384','sha512')
            and root.not_valid_before_utc<=leaf.not_valid_before_utc
            and leaf.not_valid_before_utc.timestamp()<=now<now+60<leaf.not_valid_after_utc.timestamp()
            and leaf.not_valid_after_utc<=root.not_valid_after_utc,'ticket-iam-leaf')
        usage(leaf.extensions,tls['hostname']);leaf.verify_directly_issued_by(root)
        leaves.append(int(leaf.not_valid_after_utc.timestamp()))
    require(len({public['tls'][r]['key_sha256'] for r in setup.ROLES})==3,'ticket-iam-tls-key-reuse')
    return min(leaves)

def document(statements):return {'Version':'2012-10-17','Statement':statements}
def utc(stamp):return datetime.fromtimestamp(stamp,timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

def proposal(review,expected,public,public_pin,*,expires_at):
    """Return proposed JSON only, bound to one reviewed unfunded key session.

    Expiry limits authorization too; it does not revoke the underlying key or
    count KMS calls. MFA is required and must be confirmed in real CloudShell.
    Existing-key policy replacement/merging is intentionally not supported.
    """
    review=copy.deepcopy(review);public=copy.deepcopy(public);now=int(time.time())
    end=admit(review,expected,public,public_pin,now)
    require(type(expires_at) is int and now+600<=expires_at<=now+3600
        and expires_at<end-60,'ticket-iam-window')
    expiry=utc(expires_at);nonce=review['session_id'];source='nockapp-setup-'+nonce
    roles={};operator=[];key_additions={}
    for role in setup.ROLES:
        arn=ROLE_PREFIX+role;item=review['plan']['roles'][role];key=item['kms_key_arn']
        context={'application':'nockapp-ticket-backend-v1','role':role,'backend-sha256':item['backend_sha256']}
        assume_conditions={'StringEquals':{'sts:SourceIdentity':source,'sts:RoleSessionName':session_name(role,nonce)},
            'Bool':{'aws:MultiFactorAuthPresent':'true'},'DateLessThan':{'aws:CurrentTime':expiry}}
        # SetSourceIdentity is a permission-only dependent action, whose
        # supported STS condition is SourceIdentity, not RoleSessionName.
        # The required AssumeRole permission retains the exact session name;
        # both statements retain MFA, source identity and the expiry fence.
        source_conditions=copy.deepcopy(assume_conditions)
        source_conditions['StringEquals'].pop('sts:RoleSessionName')
        pairs=[('sts:AssumeRole',assume_conditions),('sts:SetSourceIdentity',source_conditions)]
        trust=document([{'Effect':'Allow','Principal':{'AWS':OPERATOR},
            'Action':action,'Condition':copy.deepcopy(conditions)} for action,conditions in pairs])
        operator.extend({'Effect':'Allow','Action':action,
            'Resource':arn,'Condition':copy.deepcopy(conditions)} for action,conditions in pairs)
        equals={'aws:SourceIdentity':source,'aws:RequestedRegion':REGION,
            **{'kms:EncryptionContext:'+k:v for k,v in context.items()}}
        condition={'StringEquals':equals,'ForAllValues:StringEquals':{'kms:EncryptionContextKeys':sorted(context)},
            'DateLessThan':{'aws:CurrentTime':expiry}}
        grant={'Sid':'SealReviewedNewHostKeys','Effect':'Allow','Action':'kms:GenerateDataKey',
            'Resource':key,'Condition':condition}
        statements=[grant,{'Sid':'IdentifyThisSession','Effect':'Allow','Action':'sts:GetCallerIdentity','Resource':'*'},
            {'Sid':'DenyOtherOperations','Effect':'Deny','NotAction':['kms:GenerateDataKey','sts:GetCallerIdentity'],'Resource':'*'},
            {'Sid':'DenyOtherKeys','Effect':'Deny','Action':'kms:GenerateDataKey','NotResource':key},
            {'Sid':'DenyExpiredSetup','Effect':'Deny','Action':'kms:GenerateDataKey','Resource':'*',
                'Condition':{'DateGreaterThanEquals':{'aws:CurrentTime':expiry}}},
            {'Sid':'DenyExtraContext','Effect':'Deny','Action':'kms:GenerateDataKey','Resource':'*',
                'Condition':{'ForAnyValue:StringNotEquals':{'kms:EncryptionContextKeys':sorted(context)}}}]
        for index,(name,value) in enumerate(sorted(equals.items())):
            statements.append({'Sid':'DenyWrongOrMissingField'+str(index),'Effect':'Deny',
                'Action':'kms:GenerateDataKey','Resource':'*',
                'Condition':{'StringNotEqualsIfExists':{name:value}}})
        permission=document(statements)
        require(len(canonical(permission))<=6144,'ticket-iam-policy-size')
        fragment=copy.deepcopy(grant);fragment['Sid']+=role.capitalize()
        fragment['Principal']={'AWS':arn};fragment['Resource']='*'
        key_additions.setdefault(key,[]).append(fragment)
        roles[role]={'role_name':arn.rsplit('/',1)[1],'role_arn':arn,'max_session_duration':3600,
            'requested_session_seconds':900,'trust':trust,'identity_policy':permission,
            'permissions_boundary':copy.deepcopy(permission),'encryption_context':context,
            'existing_role_must_be_absent':True}
    return {'profile':PROFILE,'proposal_only':True,'review_sha256':expected,'public_keys_sha256':public_pin,
        'session_id':nonce,'plan_sha256':review['plan_sha256'],'expires_at':expires_at,'mfa_required':True,
        'roles':roles,'operator_identity_policy_addition':document(operator),
        'kms_key_policy_additions_for_independent_review':key_additions,'documentation':dict(DOCUMENTATION),
        'aws_changes_executed':False,'effective_permissions_verified':False,'can_deploy':False,'can_fund':False,
        'unresolved':['Protected host-service CA signing/recovery/automatic renewal is not implemented here; original workload CA is ineligible',
            'Administrator must verify dedicated symmetric KMS keys and full existing key policies/grants/SCPs; never replace an existing key policy with these fragments',
            'Require absent setup roles/boundary names, attach the boundary at creation, independently validate/simulate policies and verify actual AWS behavior',
            'Confirm operator MFA context survives CloudShell forwarding; do not relax conditions on failure',
            'IAM role duration floor is 3600 seconds; sender requests 900 seconds. No IAM one-use or cost quota is claimed',
            'Setup does not grant runtime decrypt/storage, CA signing, service installation, original issuer access or funds']}

def simulation_inputs(value):
    """Public SimulateCustomPolicy inputs; no execution or effective-IAM claim.

    Does not test role trust, MFA forwarding, key policy/grants or organization
    policies. Those require separate live review even if every case passes.
    """
    require(type(value) is dict and value.get('profile')==PROFILE and value.get('proposal_only') is True,
        'ticket-iam-simulation-proposal')
    now=int(time.time());require(now<value['expires_at'],'ticket-iam-simulation-expired')
    result=[]
    for role in setup.ROLES:
        item=value['roles'][role];policy=item['identity_policy']
        key=policy['Statement'][0]['Resource']
        context={'aws:SourceIdentity':'nockapp-setup-'+value['session_id'],'aws:RequestedRegion':REGION,
            'aws:CurrentTime':utc(now),'kms:EncryptionContextKeys':sorted(item['encryption_context']),
            **{'kms:EncryptionContext:'+k:v for k,v in item['encryption_context'].items()}}
        cases=[('reviewed-seal','kms:GenerateDataKey',key,context,'allowed')]
        for field in ('aws:SourceIdentity','aws:RequestedRegion','kms:EncryptionContext:application',
                      'kms:EncryptionContext:role','kms:EncryptionContext:backend-sha256'):
            wrong=copy.deepcopy(context);wrong[field]='wrong'
            absent=copy.deepcopy(context);absent.pop(field)
            cases.extend([(field+'-wrong','kms:GenerateDataKey',key,wrong,'explicitDeny'),
                          (field+'-missing','kms:GenerateDataKey',key,absent,'explicitDeny')])
        extra=copy.deepcopy(context);extra['kms:EncryptionContextKeys'].append('issuer')
        expired=copy.deepcopy(context);expired['aws:CurrentTime']=utc(value['expires_at'])
        cases.extend([('extra-context','kms:GenerateDataKey',key,extra,'explicitDeny'),
            ('expired','kms:GenerateDataKey',key,expired,'explicitDeny'),
            ('original-issuer-key','kms:GenerateDataKey',ORIGINAL_KMS,context,'explicitDeny')])
        for action in ('kms:Decrypt','kms:Sign','kms:CreateGrant','sts:AssumeRole','s3:GetObject','dynamodb:GetItem'):
            # Use service-appropriate resources rather than invalid cross-service ARNs.
            resource=key if action.startswith('kms:') else (
                'arn:aws:iam::'+ACCOUNT+':role/nockapp-zkid-issuer' if action.startswith('sts:') else
                'arn:aws:s3:::nockapp-forbidden-fixture/private' if action.startswith('s3:') else
                'arn:aws:dynamodb:'+REGION+':'+ACCOUNT+':table/nockapp-zkid')
            cases.append((action,action,resource,context,'explicitDeny'))
        for label,action,resource,fields,expected in cases:
            entries=[{'ContextKeyName':name,'ContextKeyValues':v if type(v) is list else [v],
                'ContextKeyType':'stringList' if type(v) is list else 'date' if name=='aws:CurrentTime' else 'string'}
                for name,v in sorted(fields.items())]
            result.append({'role':role,'case':label,'expected_decision':expected,'request':{
                'PolicyInputList':[canonical(policy).decode()],
                'PermissionsBoundaryPolicyInputList':[canonical(item['permissions_boundary']).decode()],
                'ActionNames':[action],'ResourceArns':[resource],'ContextEntries':entries}})
    return result
