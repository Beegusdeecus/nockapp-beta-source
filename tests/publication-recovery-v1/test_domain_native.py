"""Native framing/origin/consent/pinned-config boundary; synthetic inputs only."""
import copy
import hashlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import Mock,patch

import domain_native as native
from policy import Rejected,canonical
from test_domain_transport import fixture


def message(operation,body):return {'profile':native.PROFILE,'id':'12'*16,'operation':operation,'body':body}


class DomainNativeTests(unittest.TestCase):
    def test_01_exact_chrome_and_firefox_admission(self):
        chrome={'kind':'chrome','origin':'chrome-extension://'+'a'*32+'/'}
        firefox={'kind':'firefox','extension_id':'zkid-synthetic@example.invalid','manifest_path':'/synthetic/com.nockapp.zkid.json'}
        native.authorize([chrome['origin']],chrome)
        native.authorize([firefox['manifest_path'],firefox['extension_id']],firefox)
        for args,config in [([],chrome),([chrome['origin'],'extra'],chrome),(['chrome-extension://'+'b'*32+'/'],chrome),
                            ([firefox['extension_id']],firefox),(['/other',firefox['extension_id']],firefox),
                            ([firefox['manifest_path'],'other@example.invalid'],firefox)]:
            with self.assertRaises(Rejected):native.authorize(args,config)

    def test_02_native_framing_is_bounded_duplicate_free_and_truncation_safe(self):
        for data in [struct.pack('=I',0),struct.pack('=I',native.MAX_MESSAGE+1),b'\x00',
                     struct.pack('=I',13)+b'{"a":1,"a":2}',struct.pack('=I',8)+b'{}']:
            with self.assertRaises(Rejected):native.receive(io.BytesIO(data))
        self.assertIsNone(native.receive(io.BytesIO()))

    def test_03_public_native_roundtrip_returns_only_allowed_projection(self):
        bridge=Mock();bridge.local_status.return_value={'state':'empty','verified':False}
        app=native.NativeApplication(bridge);source=io.BytesIO();target=io.BytesIO()
        native.send(source,message('status',{}));source.seek(0);native.serve(source,target,app);target.seek(0)
        result=native.receive(target)
        self.assertEqual(result['id'],'12'*16);self.assertFalse(result['verified'])
        self.assertEqual(result['result']['state'],'empty');bridge.local_status.assert_called_once()

    def test_04_caller_cannot_supply_paths_trust_sessions_proofs_or_eligibility(self):
        bridge=Mock();app=native.NativeApplication(bridge)
        for operation,body in [('begin',{'username':'synthetic','approve_public_profile_lookup':True,'trust':{}}),
                               ('check-post',{'post':'12345','approve_source_check':True,'session':{}}),
                               ('recover',{'path':'/synthetic'}),('cancel',{'state':'aborted'}),
                               ('verify',{'proof':{}}),('sign',{'followers':10000})]:
            self.assertEqual(app.dispatch(message(operation,body))['status'],'rejected')
        self.assertEqual(bridge.mock_calls,[])

    def test_05_source_and_local_deletion_consents_precede_controller(self):
        bridge=Mock();app=native.NativeApplication(bridge)
        for operation,body in [('begin',{'username':'synthetic','approve_public_profile_lookup':False}),
                               ('check-post',{'post':'12345','approve_source_check':1}),
                               ('forget',{'confirm_local_deletion':False})]:
            self.assertEqual(app.dispatch(message(operation,body))['status'],'rejected')
        self.assertEqual(bridge.mock_calls,[])

    def test_06_proof_requires_exact_fact_and_identity_consents(self):
        bridge=Mock();bridge.present.return_value={'synthetic':'public-proof'};app=native.NativeApplication(bridge)
        challenge={'profile':native.CREDENTIAL,'nonce':'11'*32,'scope':'22'*32,'facts':['account-controlled'],
                   'identity':True,'registry_sequence':1,'created_at':1793011200,'expires_at':1793011260}
        body={'challenge':challenge,'approve_facts':[],'approve_identity_disclosure':False}
        self.assertEqual(app.dispatch(message('present',body))['status'],'rejected');bridge.present.assert_not_called()
        body['approve_facts']=challenge['facts'];self.assertEqual(app.dispatch(message('present',body))['status'],'rejected')
        body['approve_identity_disclosure']=True
        self.assertEqual(app.dispatch(message('present',body))['status'],'ok');bridge.present.assert_called_once_with(challenge)

    def test_07_private_exception_text_never_reaches_native_output(self):
        bridge=Mock();bridge.recover.side_effect=RuntimeError('SYNTHETIC-PRIVATE-MARKER')
        result=native.NativeApplication(bridge).dispatch(message('recover',{}))
        self.assertNotIn(b'SYNTHETIC-PRIVATE-MARKER',canonical(result));self.assertFalse(result['verified'])

    def test_only_fixed_publication_recovery_conditions_are_projected(self):
        cases=[('public-publish',Rejected('follower-publication-window-too-short'),'publication-follower-window-unavailable'),
               ('public-publish',Rejected('ticket-wallet-empty'),'publication-ticket-needed'),
               ('public-outbox',Rejected('ticket-wallet-empty'),'native-operation-unavailable'),
               ('public-publish',Rejected('SYNTHETIC-PRIVATE-MARKER'),'native-operation-unavailable'),
               ('public-publish',RuntimeError('SYNTHETIC-PRIVATE-MARKER'),'native-operation-unavailable')]
        for operation,error,expected in cases:
            public=Mock();public.dispatch.side_effect=error
            result=native.NativeApplication(None,public_app=public).dispatch(message(operation,{}))
            self.assertEqual(result['code'],expected)
            self.assertNotIn(b'SYNTHETIC-PRIVATE-MARKER',canonical(result))
            self.assertEqual(set(result),{'profile','id','status','code','recoverable','laboratory','verified'})

    def test_08_installer_pins_all_code_and_approval_before_opening_wallet_or_stdin(self):
        with tempfile.TemporaryDirectory(prefix='zkid-native-config-') as temporary:
            root=Path(temporary);pins={}
            for name in native.REQUIRED:
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'synthetic-public-code')
                pins[name]=hashlib.sha256(p.read_bytes()).hexdigest()
            config={'profile':native.PROFILE,'browser':{'kind':'chrome','origin':'chrome-extension://'+'a'*32+'/'},
                    'issuer_approval':fixture()[1],'issuer_port':19440,'wallet_directory':str(root/'wallet'),
                    'files_sha256':pins}
            p=root/'domain-native-config.json';p.write_bytes(canonical(config));p.chmod(0o600)
            with patch.object(native,'ROOT',root):
                self.assertEqual(native.configuration(),config)
                remote={key:value for key,value in config.items() if key!='issuer_port'}
                remote['issuer_endpoint']={'profile':'nockapp-zkid-public-issuer-endpoint-v1',
                                          'host':'issuer.example.com','port':443}
                p.write_bytes(canonical(remote));self.assertEqual(native.configuration(),remote)
                from test_post_remote_transport import approval
                verifier=approval(remote['issuer_approval']['definition_hash'],pins['domain-crypto/target/debug/nockapp-zkid-domain-research'])
                full={**remote,'verifier_approval':verifier}
                p.write_bytes(canonical(full));self.assertEqual(native.configuration(),full)
                with patch.object(native,'configuration',return_value=full),patch.object(native,'authorize'),\
                     patch.object(native,'DomainBridge') as create,patch.object(native,'PostHolder') as holder,patch.object(native,'serve'):
                    self.assertEqual(native.main(),0);holder.assert_called_once_with(create.return_value,verifier)
                with patch.object(native,'configuration',return_value=remote),patch.object(native,'authorize'),\
                     patch.object(native,'DomainBridge') as create,patch.object(native,'serve'):
                    self.assertEqual(native.main(),0)
                    create.assert_called_once_with(remote['wallet_directory'],remote['issuer_approval'],endpoint=remote['issuer_endpoint'])
                p.write_bytes(canonical({**remote,'issuer_port':19440}))
                with self.assertRaises(Rejected):native.configuration()
                p.write_bytes(canonical(config))
                (root/'domain_bridge.py').write_bytes(b'changed')
                with self.assertRaises(Rejected):native.configuration()
                with patch.object(native,'DomainBridge') as create:
                    self.assertEqual(native.main(),1);create.assert_not_called()
