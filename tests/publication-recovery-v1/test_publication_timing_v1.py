"""Public submission fixtures; no owner credential or keyring access."""
import unittest
from types import SimpleNamespace
from unittest.mock import Mock,patch
from policy import canonical,Rejected
from public_bundle_v5 import blob
from public_desktop_v5 import PublicDesktopV5
from public_native_v5 import PublicApplicationV5
from renewal_evidence_v3 import PROFILE

class PublicationTimingTests(unittest.TestCase):
    def test_optional_badge_recovery_needs_exact_separate_publish_consent(self):
        desktop=Mock();app=PublicApplicationV5(desktop)
        for operation,extra in (('public-publish',False),('public-publish',1),('public-finish',True)):
            with self.assertRaises(Rejected):
                app.dispatch(operation,{'post_id':'synthetic','approve_publication':True,'approve_optional_badge_failure':extra})
        desktop.publish.assert_not_called();desktop.finish.assert_not_called()
        app.dispatch('public-publish',{'post_id':'synthetic','approve_publication':True,'approve_optional_badge_failure':True})
        desktop.publish.assert_called_once_with('synthetic',True,approve_optional_badge_failure=True)
    def row(self):
        return {'bundle':{'unsigned':{'core':{'selection':{'followers_threshold':0}},
            'evidence':{'followers':blob(canonical({'profile':PROFILE,'window_start':1000,'window_end':1060}),'followers')}}}}
    def test_exclusive_deadline_margin_and_expiry(self):
        for now,accepted in ((1000,True),(1044,True),(1045,False),(1060,False),(999,False)):
            d=SimpleNamespace(clock=lambda:now)
            if accepted:PublicDesktopV5._follower_submission_window(d,self.row())
            else:
                with self.assertRaisesRegex(Rejected,'follower-publication-window-too-short'):PublicDesktopV5._follower_submission_window(d,self.row())
    def test_missing_optional_evidence_is_unaffected(self):
        row=self.row();row['bundle']['unsigned']['evidence']['followers']=None
        PublicDesktopV5._follower_submission_window(SimpleNamespace(clock=lambda:9999),row)
    def test_unused_issuer_history_is_not_read(self):
        d=SimpleNamespace(reader=SimpleNamespace(issuer_views=Mock(),count_native=None,resolve_original=Mock()),
            clock=lambda:1000,author=SimpleNamespace(native=object()),scope={})
        with patch('public_desktop_v5.encode',return_value=b'public-fixture'),patch('indexed_authorship_v5.verify_indexed_bundle',return_value={'thread':None}) as verify:
            PublicDesktopV5._validate_for_submission(d,self.row())
        d.reader.issuer_views.current.assert_not_called();verify.assert_called_once()
