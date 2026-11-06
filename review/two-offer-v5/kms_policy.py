"""Produce a reviewable KMS key-policy fragment; performs NO AWS operation.

This fragment does not replace owner administration or prove a provisioner is
correctly configured. Approve image/signer values independently before using it.
"""
import argparse
import json
import re
from policy import Rejected, require


def fragment(role,image_pcr,signer_pcr):
    require(type(role) is str and re.fullmatch(r'arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9_+=,.@/-]+',role),
            'kms-principal')
    for value in (image_pcr,signer_pcr):
        require(type(value) is str and re.fullmatch(r'[0-9a-f]{96}',value) and any(bytes.fromhex(value)),
                'kms-unapproved-or-debug-measurement')
    principal={'AWS':role}
    statements=[]
    # Explicit deny prevents a broader Allow for this role from opening an
    # unattested plaintext decrypt route. The key-policy administrator remains
    # a trusted provisioning authority and can change policies; Nitro cannot
    # prevent an AWS administrator from changing their own account settings.
    for index,value in [('0',image_pcr),('8',signer_pcr)]:
        statements.append({'Sid':'RejectOtherOrMissingPCR'+index,'Effect':'Deny','Principal':principal,
            'Action':'kms:Decrypt','Resource':'*','Condition':{'StringNotEqualsIgnoreCase':{
                'kms:RecipientAttestation:PCR'+index:value}}})
    statements.append({'Sid':'AllowApprovedZKIDEnclave','Effect':'Allow','Principal':principal,
        'Action':'kms:Decrypt','Resource':'*','Condition':{
            'StringEqualsIgnoreCase':{'kms:RecipientAttestation:PCR0':image_pcr,'kms:RecipientAttestation:PCR8':signer_pcr},
            'StringEquals':{'kms:EncryptionContext:application':'nockapp-zkid-v1',
                            'kms:EncryptionContext:kind':['twitterapi-key','blind-issuer-key']}}})
    return {'Version':'2012-10-17','Statement':statements}


def recipient_fragment(role,image_pcr,signer_pcr,namespace,authority):
    """Current composite bootstrap, including protected managed writer secrets."""
    from provisioning import KINDS,encryption_context
    context=encryption_context('blind-issuer-key',namespace,authority)
    policy=fragment(role,image_pcr,signer_pcr)
    values={'kms:EncryptionContext:'+k:v for k,v in context.items()}
    values['kms:EncryptionContext:kind']=sorted(KINDS)
    policy['Statement'][-1]['Condition']['StringEquals']=values
    # Prevent a broader permission for this principal from bypassing namespace
    # or secret-kind restrictions. The provisioning administrator stays trusted.
    for index,(key,value) in enumerate(values.items()):
        policy['Statement'].insert(-1,{'Sid':'RejectOtherOrMissingContext'+str(index),'Effect':'Deny',
            'Principal':{'AWS':role},'Action':'kms:Decrypt','Resource':'*',
            'Condition':{'StringNotEquals':{key:value}}})
    return policy


def initial_fragment(role,image_pcr,signer_pcr,namespace,authority,issuer_role):
    """Separate INITIAL principal: scoped GDK + issuer-writer unwrap only.

    Review-only key-policy fragment, never applied by this module. Production
    parent permissions remain decrypt-only. All inputs require prior approval.
    """
    from provisioning import encryption_context
    base=fragment(role,image_pcr,signer_pcr)
    fragment(issuer_role,image_pcr,signer_pcr)  # Validate the exact writer ARN.
    require(issuer_role!=role and issuer_role.split(':')[4]==role.split(':')[4],'kms-initial-principal')
    key_context=encryption_context('blind-issuer-key',namespace,authority)
    writer_context=encryption_context('managed-writer-credentials',namespace,authority,role=issuer_role,purpose='issuer')
    principal={'AWS':role};actions=['kms:Decrypt','kms:GenerateDataKey'];statements=[]
    for item in base['Statement'][:-1]:
        item['Sid']='Initial'+item['Sid'];item['Action']=actions;statements.append(item)
    for index,(action,context) in enumerate([('kms:GenerateDataKey',key_context),('kms:Decrypt',writer_context)]):
        values={'kms:EncryptionContext:'+k:v for k,v in context.items()}
        # One deny per required value: missing OR wrong fields cannot be rescued
        # by a broader allow elsewhere for this same dedicated principal.
        for number,(key,value) in enumerate(values.items()):
            statements.append({'Sid':f'Initial{index}RejectContext{number}','Effect':'Deny','Principal':principal,
                'Action':action,'Resource':'*','Condition':{'StringNotEquals':{key:value}}})
        statements.append({'Sid':f'Initial{index}RejectExtraContext','Effect':'Deny','Principal':principal,
            'Action':action,'Resource':'*','Condition':{'ForAnyValue:StringNotEquals':{
                'kms:EncryptionContextKeys':sorted(context)}}})
        statements.append({'Sid':f'Initial{index}AllowApproved','Effect':'Allow','Principal':principal,
            'Action':action,'Resource':'*','Condition':{
                'StringEqualsIgnoreCase':{'kms:RecipientAttestation:PCR0':image_pcr,
                                         'kms:RecipientAttestation:PCR8':signer_pcr},
                'StringEquals':values,'ForAllValues:StringEquals':{'kms:EncryptionContextKeys':sorted(context)}}})
    return {'Version':'2012-10-17','Statement':statements}


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--role',required=True);p.add_argument('--image-pcr',required=True)
    p.add_argument('--signer-pcr',required=True);args=p.parse_args()
    try:print(json.dumps(fragment(args.role,args.image_pcr,args.signer_pcr),indent=2,sort_keys=True))
    except Rejected:raise SystemExit('KMS policy rejected: require independently approved nonzero image/signer measurements')
