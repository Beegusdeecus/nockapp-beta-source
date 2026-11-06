"""Freeze real package dependencies, without executing imports or private code."""
from pathlib import Path
import tempfile,unittest
from public_installation import source_files


class ClosureTests(unittest.TestCase):
    def test_packages_relative_lazy_and_init_imports_are_included_without_execution(self):
        with tempfile.TemporaryDirectory(prefix='nockapp-source-closure-') as d:
            root=Path(d)
            files={'domain_native.py':'', 'domain_native_entrypoint.py':'',
                'public_native_v6.py':'',
                'public_installation.py':'def later():\n import pkg.checkout\n',
                'pkg/__init__.py':'from . import shared\n',
                'pkg/shared.py':'raise AssertionError("never execute source")\n',
                'pkg/checkout.py':'from .inner import verifier\nfrom local_helper import helper\n',
                'pkg/inner/__init__.py':'',
                'pkg/inner/verifier.py':'from ..shared import thing\n',
                'local_helper.py':'', 'pkg/unrelated.py':'', 'unrelated.py':''}
            for name,body in files.items():
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(body)
            closure=source_files(root)
            self.assertTrue(set(files)-{'pkg/unrelated.py','unrelated.py'}<=closure)
            self.assertNotIn('pkg/unrelated.py',closure);self.assertNotIn('unrelated.py',closure)

    def test_actual_one_call_candidate_is_in_the_frozen_source_closure(self):
        closure=source_files(Path(__file__).resolve().parent)
        self.assertTrue({'batch_checkout_v2/__init__.py','batch_checkout_v2/offer.py',
            'batch_checkout_v2/payment.py','batch_checkout_v2/purchase.py'}<=closure)
