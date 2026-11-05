# Run the startup-channel diagnostic checks

From the root of this public source checkout, use an environment containing
`cryptography`. This command was tested with Python 3.14.4 and cryptography
46.0.5. It imports application code only from this checkout; no sibling private
repository, installed app, deployment configuration or native application binary
is needed. No AWS credentials, source account or Nitro device is used.

```bash
python3 -I -B - <<'PY'
from pathlib import Path
import sys,unittest
root=Path.cwd().resolve()
sys.path[:0]=[str(root/'tests/startup-diagnostics-v2'),
 str(root/'components/parent-complete-startup-diagnostics-v4'),
 str(root/'components/issuer-complete-startup-diagnostics-v2/opt/nockapp/research/zkid'),
 str(root/'components/issuer-complete-startup-diagnostics-v2/opt/TLSNotaryVendor')]
result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromName('test_boot_attestation'))
for name in ('boot_attestation','domain_transport','domain_trust','provisioning','test_provisioning','vendor_service.attestation'):
 assert Path(sys.modules[name].__file__).resolve().is_relative_to(root),name
raise SystemExit(not result.wasSuccessful())
PY
```

Expected result: eight passing tests. They exercise real local TLS with simulated
NSM/AWS verification: boot/loaded-issuer separation, binding/freshness failures,
handler delivery, fixed failure labels, the 256-byte reply bound, and rejection
of private exception messages/paths. These are synthetic protocol checks, not
fresh AWS attestation, actual startup recovery, or complete beta acceptance.
Only `test_boot_attestation` is selected. The additional provisioning tests in
the imported fixture module are outside this command's scope.

`test_provisioning.py` is the unchanged synthetic fixture from private-source
commit `6cfed9c`; its SHA-256 is
`ea28f5d829992279c1ce0b5ec2e5842172de2bc30cbd55bf269d49f53cad09ce`.
The diagnostic guest and parent snapshots remain unchanged. Full transitive
fixture distribution and whole-image reproducibility are still incomplete.
