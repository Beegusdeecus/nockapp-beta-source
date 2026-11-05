"""Real TLS and original-style CA/selected-certificate crypto; AWS/NSM fixtures.

No EC2, owner record, credential lookup or real cloud/source request occurs.
"""
from dataclasses import asdict
import base64
import copy
import hashlib
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

import boot_attestation as boot
from base_transactions import Limits
from fixed_issuer_code_v1 import sha256 as fixed_sha
from policy import canonical,digest,Rejected
import public_renewal_parent_bootstrap_v1 as parent
import public_renewal_runtime_v1 as runtime
from public_updater_keys_v1 import SCOPE,PUBLIC,PROPOSAL
from test_aws_transport import credentials
from test_renewal_transport_v3 import fixture as service_fixture
from test_workload_sessions import identity as session_fixture
import test_workload_ca as ca_fixtures
from workload_ca import scope,certificate_suffix
from workload_identity_ceremony import selection_key


class ParentBootstrapTests(unittest.TestCase):
    def setUp(self):
        ca=ca_fixtures.CATests();ca.setUp();self.addCleanup(ca.doCleanups);ca.prepare();self.ca=ca
        for purpose in runtime.PURPOSES:ca.ca.issue(purpose)
        issuer=ca.f.config['issuer'];ns=issuer['authority']['namespace'];authority=ca.f.authority
        service=service_fixture()['identity'];service['definition_hash']=ns
        service['runtime_code'][service['registry']]=fixed_sha(service['updater'],ns)
        root=ca.ca.public()
        workloads={}
        for purpose in runtime.PURPOSES:
            cfg,_,_=session_fixture(purpose)
            workloads[purpose]={k:cfg[k] for k in ('trust_anchor_arn','profile_arn','duration_seconds')}
        fee={'max_l1_fee':10**13,'max_operator_fee':10**13,'max_total_fee':10**16,'total_budget':10**18,
            'funded_budget':10**18,'max_head_age':60,'oracle_implementation':'0x'+'67'*20,
            'l1_block_implementation':'0x'+'68'*20,**{k:'69'*32 for k in ('oracle_proxy_sha256',
                'oracle_implementation_sha256','l1_block_proxy_sha256','l1_block_implementation_sha256')}}
        selected_scope={'profile':SCOPE,'chain_id':84532,'definition':ns,'application':service['application'],'authority':authority}
        proposal={'profile':PROPOSAL,'chain_id':84532,'definition':ns,'application':service['application'],'updater':service['updater']}
        self.config={'profile':runtime.PROFILE_SELECTED,'issuer':issuer,'service':service,'root_certificate':root['root_certificate'],
            'root_sha256':root['root_sha256'],'workloads':workloads,'rpc_endpoint':'https://sepolia.base.org','reservation_batch':2,
            'limits':asdict(Limits(1000000,3000000000,1000000,10**17,20)),'fee_policy':fee,
            'updater_selection':{'profile':PUBLIC,'scope':selected_scope,'proposal':proposal,'selection_sha256':'12'*32}}
        self.approved=ca.f.approved
        self.packet={'profile':parent.PACKET,'issuer_config_sha256':digest(issuer),'encrypted_secrets':{
            kind:base64.b64encode(('synthetic-ciphertext-'+kind).encode()).decode() for kind in ('blind-issuer-key','twitterapi-key')}}
        account=issuer['kms_key_arn'].split(':')[4]
        self.identity={'instance':'i-07cdced76336a314e','region':'ap-southeast-2',
            'role_arn':'arn:aws:iam::'+account+':role/'+parent.HOST_ROLE,
            'profile_arn':'arn:aws:iam::'+account+':instance-profile/'+parent.HOST_ROLE}
        self.value=parent.plan(self.config,self.approved,digest(self.packet),self.identity,'serving')

    def exchange(self,*,bad_quote=False,bad_tls=False,bad_sts=False,progress=None,handler_error=None,expected_boot_error=None):
        client,server=socket.socketpair();received=[];trace={'delivery_attempted':False};results=[]
        def verify(document,now):
            payload=self.ca.f.payload()
            if bad_quote:payload['nonce']=b'wrong'
            return payload
        def handler(body):
            received.append(body)
            if handler_error is not None:raise handler_error
            return True
        def serve():results.append(boot.serve_boot(server,self.ca.f.nsm,self.approved['code_identity'],
            self.approved['state_authority_sha256'],self.approved['definition_hash'],handler))
        with patch.object(boot,'verify_aws_document',side_effect=verify),patch.object(parent,'credentials',return_value=credentials()) as imds,\
             patch.object(parent,'StsIdentityClient') as sts,patch.object(parent,'AwsJsonClient',return_value=self.ca.f.sdk) as aws,\
             patch.object(parent,'tls_context',return_value=object()),patch.object(self.ca.f.sdk,'get_item',wraps=self.ca.f.sdk.get_item) as reads:
            if bad_sts:sts.return_value.verify.side_effect=Rejected('synthetic-wrong-role')
            with context_patch(bad_tls):
                thread=threading.Thread(target=serve);thread.start()
                try:
                    if bad_quote or bad_tls or bad_sts or handler_error is not None:
                        with self.assertRaisesRegex(Rejected,expected_boot_error or '.'):
                            parent.execute(client,self.config,self.approved,self.packet,self.value,digest(self.value),trace,progress=progress)
                        reply=None
                    else:reply=parent.execute(client,self.config,self.approved,self.packet,self.value,digest(self.value),trace,progress=progress)
                finally:client.close();thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            if bad_quote or bad_tls:imds.assert_not_called();sts.assert_not_called();aws.assert_not_called()
            elif bad_sts:imds.assert_called_once();aws.assert_not_called()
            else:
                imds.assert_called_once_with(self.identity);sts.return_value.verify.assert_called_once_with(self.identity['role_arn'])
                self.assertEqual(reads.call_count,6)
                self.assertTrue(all(c.kwargs['ConsistentRead'] is True for c in reads.call_args_list))
        return received,trace,reply

    def test_real_tls_recovers_only_six_selected_public_heads_and_delivers_once(self):
        rows_before=copy.deepcopy(self.ca.f.sdk.rows);received,trace,result=self.exchange()
        self.assertEqual(self.ca.f.sdk.rows,rows_before);self.assertTrue(trace['delivery_attempted'])
        self.assertEqual(len(received),1);envelope=received[0]
        self.assertEqual(envelope['profile'],runtime.PROFILE_SELECTED);self.assertEqual(set(envelope['identities']),set(runtime.PURPOSES))
        self.assertEqual(envelope['encrypted_secrets'],self.packet['encrypted_secrets'])
        self.assertFalse(result['service_ready']);self.assertFalse(result['credentials_saved'])
        self.assertNotIn(credentials()['secret_access_key'],canonical(result).decode())

    def test_bad_quote_tls_possession_or_sts_never_delivers_private_boot(self):
        for flags in ({'bad_quote':True},{'bad_tls':True},{'bad_sts':True}):
            with self.subTest(flags=flags):
                received,trace,_=self.exchange(**flags);self.assertEqual(received,[]);self.assertFalse(trace['delivery_attempted'])

    def test_safe_progress_distinguishes_channel_identity_and_payload_without_private_values(self):
        for flags,last in (({'bad_quote':True},'bootstrap-channel'),({'bad_tls':True},'bootstrap-channel'),
                ({'bad_sts':True},'bootstrap-caller-identity'),({},'bootstrap-acknowledged')):
            stages=[]
            with self.subTest(flags=flags):
                received,trace,result=self.exchange(**flags,progress=stages.append)
                self.assertEqual(stages[-1],last)
                allowed={'bootstrap-channel','bootstrap-credentials','bootstrap-caller-identity',
                    'bootstrap-selected-identities','bootstrap-envelope-validation','bootstrap-delivery-ready','bootstrap-acknowledged'}
                self.assertTrue(set(stages)<=allowed)
                self.assertNotIn(credentials()['secret_access_key'],canonical(stages).decode())
                if flags:self.assertFalse(trace['delivery_attempted']);self.assertEqual(received,[])

    def test_attested_initialization_failure_is_reported_without_retry_or_private_error_text(self):
        for error,expected in ((Rejected('transaction-journal-context'),'enclave-startup:transaction-journal-context'),
                (RuntimeError('SYNTHETIC-PRIVATE-ERROR'),'enclave-startup:startup-unknown-other')):
            with self.subTest(expected=expected):
                received,trace,result=self.exchange(handler_error=error,expected_boot_error=expected)
                self.assertEqual(len(received),1);self.assertTrue(trace['delivery_attempted']);self.assertIsNone(result)

    def test_unknown_encrypted_failure_label_is_not_reflected_to_parent_diagnostics(self):
        with patch.object(boot,'initialization_failure_code',return_value='SYNTHETIC-PRIVATE-REPLY'):
            received,trace,result=self.exchange(handler_error=Rejected('budget-item'),expected_boot_error='parent-boot-rejected')
        self.assertEqual(len(received),1);self.assertTrue(trace['delivery_attempted']);self.assertIsNone(result)

    def test_migration_uses_only_explicit_preservation_wrapper_over_same_boot_protocol(self):
        self.config={'profile':parent.migration.PROFILE,'runtime':self.config,'initial_nonce':0,
            'expected_source':{'revision':9,'public_sha256':'12'*32},
            'deployment':{'transaction_hash':'0x'+'12'*32,'block_hash':'0x'+'34'*32,'block_number':1}}
        self.value=parent.plan(self.config,self.approved,digest(self.packet),self.identity,'migration')
        received,trace,result=self.exchange();self.assertTrue(trace['delivery_attempted'])
        self.assertEqual(set(received[0]),{'profile','operation','recovery'})
        self.assertEqual(received[0]['profile'],parent.migration.BOOT)
        self.assertEqual(received[0]['operation'],'preserve-and-commit')
        self.assertEqual(received[0]['recovery']['profile'],runtime.PROFILE_SELECTED)
        self.assertFalse(result['migration_finality_verified'])

    def test_changed_public_pins_and_extra_packet_authority_stop_before_quote_or_imds(self):
        for changed in ({**self.packet,'credentials':{}},{**self.packet,'issuer_config_sha256':'12'*32}):
            value=parent.plan(self.config,self.approved,digest(changed),self.identity,'serving')
            with patch.object(parent,'provision_boot_lazy') as channel,patch.object(parent,'credentials') as imds,self.assertRaises(Rejected):
                parent.execute(None,self.config,self.approved,changed,value,digest(value),{})
            channel.assert_not_called();imds.assert_not_called()
        for key,value in (('role_arn',self.identity['role_arn']+'-other'),('region','us-east-1')):
            with self.assertRaises(Rejected):parent.plan(self.config,self.approved,digest(self.packet),{**self.identity,key:value},'serving')

    def test_selected_identity_and_certificate_substitution_fails_closed(self):
        ns=self.config['issuer']['authority']['namespace'];key=self.config['issuer']['kms_key_arn'];authority=self.ca.f.authority
        objects=self.ca.ca.objects
        for suffix in (selection_key(ns,authority,key,'issuer'),certificate_suffix(scope(ns,authority,key),'issuer')):
            record_key=('synthetic-table',objects.key(suffix)['id']['S']);original=copy.deepcopy(self.ca.f.sdk.rows[record_key])
            self.ca.f.sdk.rows[record_key]['data']['B']=b'{}'
            with self.assertRaises(Rejected):parent.selected_records(self.ca.f.sdk,self.config,authority)
            self.ca.f.sdk.rows[record_key]=original

    def test_ciphertext_record_requires_private_mode_canonical_json_and_no_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'packet.json';path.write_bytes(canonical(self.packet)+b'\n');path.chmod(0o600)
            self.assertEqual(parent.read_record(path,private=True),self.packet)
            path.chmod(0o644)
            with self.assertRaises(Rejected):parent.read_record(path,private=True)
            path.chmod(0o600);link=Path(temporary)/'link.json';link.symlink_to(path)
            with self.assertRaises(Rejected):parent.read_record(link,private=True)
            path.write_bytes(canonical(self.packet)+b'\n\n')
            with self.assertRaises(Rejected):parent.read_record(path,private=True)


def context_patch(bad_tls):
    from contextlib import nullcontext
    if not bad_tls:return nullcontext()
    import parent_boot_channel_v1
    return patch.object(parent_boot_channel_v1,'pinned_channel_context',side_effect=Rejected('synthetic-tls-failure'))


if __name__=='__main__':unittest.main()
