"""Fixed-path offline proposal admission inside the pinned frozen runtime."""
import argparse
from pathlib import Path
from policy import canonical,require
from ticket_backend_boot_v1 import harden_process
from ticket_service_plan_v1 import verify_review

def main(argv=None):
    class Parser(argparse.ArgumentParser):
        def error(self,_):raise ValueError('ticket-plan-admission-arguments')
    try:
        harden_process();parser=Parser(description=__doc__)
        parser.add_argument('--review-sha256',required=True);parser.add_argument('--release-sha256',required=True)
        args=parser.parse_args(argv)
        result=verify_review(Path('/review'),args.review_sha256,Path('/package'),args.release_sha256)
        require(result['proposal_integrity_checked'],'ticket-plan-admission')
        print(canonical({'ok':True,'profile':'nockapp-ticket-plan-admission-v1',
            'review_sha256':args.review_sha256,'release_sha256':args.release_sha256,
            'proposal_integrity_checked':True,'synthetic_only':result['synthetic_only'],
            'keys_opened':False,'host_verified':False,'installed':False}).decode(),flush=True);return 0
    except Exception:
        print(canonical({'ok':False,'error':'ticket-plan-admission-unavailable'}).decode(),flush=True);return 1

if __name__=='__main__':raise SystemExit(main())
