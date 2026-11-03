"""Fixed-path public admission of the explicit six-process renewable plan."""
import argparse
from pathlib import Path

from policy import canonical,require
from ticket_backend_boot_v1 import harden_process
from ticket_service_plan_v2 import verify_review

PROFILE='nockapp-ticket-plan-admission-with-ca-v2'


def main(argv=None):
    class Parser(argparse.ArgumentParser):
        def error(self,_):raise ValueError('ticket-ca-plan-admission-arguments')
    try:
        harden_process();parser=Parser(description=__doc__)
        parser.add_argument('--review-sha256',required=True);parser.add_argument('--release-sha256',required=True)
        args=parser.parse_args(argv)
        result=verify_review(Path('/review'),args.review_sha256,Path('/package'),args.release_sha256)
        require(result['proposal_integrity_checked'],'ticket-ca-plan-admission')
        print(canonical({'ok':True,'profile':PROFILE,'review_sha256':args.review_sha256,
            'release_sha256':args.release_sha256,'proposal_integrity_checked':True,
            'synthetic_only':result['synthetic_only'],'keys_opened':False,
            'credentials_acquired':False,'host_verified':False,'installed':False}).decode(),flush=True)
        return 0
    except Exception:
        print(canonical({'ok':False,'profile':PROFILE,'error':'ticket-ca-plan-admission-unavailable'}).decode(),flush=True)
        return 1


if __name__=='__main__':raise SystemExit(main())
