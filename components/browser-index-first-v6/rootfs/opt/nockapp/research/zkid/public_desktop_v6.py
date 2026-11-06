"""Index-first publication, durable delivery backoff and exact-byte restoration.

Keeps the original outbox/author/ticket records. Delivery state is separate public
metadata. Only an attempted, owner-approved publication may be restored; unsent
drafts and signed-but-unsent bundles never upload automatically.
"""
import copy
from policy import require
from base_protocol import sha
from permissionless_index import digest as hash32
from public_bundle_v5 import encode,MAX_BYTES
from public_desktop_v5 import PublicDesktopV5,follower_window_status

DELIVERY='nockapp-public-content-delivery-v1'
STATES={'pending-index','delivered','origin-unavailable','restore-unavailable','invalid'}

class IndexFirstDesktop(PublicDesktopV5):
    record_names=PublicDesktopV5.record_names|{'delivery.json'}

    def _delivery(self):
        value=self._read('delivery.json',missing=True)
        if value is None:return {'profile':DELIVERY,'entries':{}}
        require(type(value) is dict and set(value)=={'profile','entries'}and value['profile']==DELIVERY
            and type(value['entries']) is dict and len(value['entries'])<=40,'delivery-record')
        for h,row in value['entries'].items():
            hash32(h);require(type(row) is dict and set(row)=={'state','attempts','next_check','checked_at','initial_delivery_attempted'}
                and row['state'] in STATES and type(row['attempts']) is int and 0<=row['attempts']<=20
                and type(row['initial_delivery_attempted']) is bool
                and all(type(row[k]) is int and 0<=row[k]<2**63 for k in ('next_check','checked_at')),'delivery-record')
        return value

    def _check_locked(self,box,r,*,force=False):
        require(r['bundle'] is not None,'v5-bundle-unsaved')
        h=sha(encode(r['bundle']));now=int(self.clock());delivery=self._delivery();previous=delivery['entries'].get(h)
        if previous is not None and now<previous['next_check'] and not force:
            return self._projection(r)
        r['status']=super()._canonical(r)
        state='pending-index'
        attempted=(previous or {}).get('initial_delivery_attempted',False)
        if r['status']['state']=='invalid':state='invalid'
        elif r['status']['state']=='finalized'and r['last_attempt'] is not None:
            # The independent reader checked mandatory public proofs against
            # finalized inclusion using these exact locally retained bytes.
            observation=self.content.origin.probe(h,MAX_BYTES)
            if observation.get('state')=='present':state='delivered'
            elif observation.get('state')in ('missing','corrupt')or observation.get('state')=='inaccessible'and not attempted:
                attempted=True
                # Commit the initial-delivery fence BEFORE any write, including
                # an uncertain upload.403 is not absence; this allows just one
                # safe conditional-create attempt, then read-only/backoff checks.
                delivery['entries'][h]={'state':'restore-unavailable','attempts':min(20,(previous or {}).get('attempts',0)+1),
                    'next_check':now+300,'checked_at':now,'initial_delivery_attempted':True}
                self._write('delivery.json',delivery)
                try:
                    self.content.restore(r['bundle']);state='delivered'
                except Exception:state='restore-unavailable'
            else:state='origin-unavailable'
            if state!='delivered':r['status']['state']='content-unavailable'
        attempts=0 if state=='delivered'else min(20,(previous or {}).get('attempts',0)+1)
        delay=60 if state=='delivered'else min(300,5*2**min(attempts,6))
        delivery['entries'][h]={'state':state,'attempts':attempts,'next_check':now+delay,'checked_at':now,
            'initial_delivery_attempted':attempted or state=='delivered'}
        self._write('outbox.json',box);self._write('delivery.json',delivery)
        return self._projection(r,fresh=True)

    def check(self,post_id):
        with self.lock():
            box=self._outbox();return self._check_locked(box,self._row(box,post_id))

    def reconcile(self,limit=4):
        require(type(limit) is int and 1<=limit<=4,'delivery-work-limit')
        with self.lock():
            box=self._outbox();delivery=self._delivery();now=int(self.clock())
            approved=[r for r in box['entries']if r['bundle'] is not None and r['last_attempt'] is not None]
            completed=[r for r in approved if r['status'] is not None and r['status']['state']=='finalized'][-5:]
            selected=[r for r in approved if r in completed or r['status'] is None or r['status']['state']!='finalized']
            due=[]
            for r in selected:
                h=sha(encode(r['bundle']));entry=delivery['entries'].get(h)
                if entry is None or entry['next_check']<=now:due.append((0 if entry is None else entry['checked_at'],r))
            due.sort(key=lambda item:(item[0],item[1]['core']['post']['id']))
            checked=[]
            for _,r in due[:limit]:
                try:checked.append(self._check_locked(box,r))
                except Exception:
                    # Preserve exact bytes and approval; an unavailable RPC is
                    # neither absence nor authority to upload or index again.
                    h=sha(encode(r['bundle']));current=self._delivery()
                    previous=current['entries'].get(h,{});attempts=min(20,previous.get('attempts',0)+1)
                    current['entries'][h]={'state':'origin-unavailable','attempts':attempts,
                        'next_check':now+min(300,5*2**min(attempts,6)),'checked_at':now,
                        'initial_delivery_attempted':previous.get('initial_delivery_attempted',False)}
                    self._write('delivery.json',current)
            return checked

    def outbox(self,after=0,limit=8):
        if after==0:self.reconcile(4)
        return super().outbox(after,limit)

    def publish(self,post_id,approve_publication,*,approve_optional_badge_failure=False):
        require(approve_publication is True and type(approve_optional_badge_failure) is bool,'consent-required')
        with self.lock():
            box=self._outbox();r=self._row(box,post_id)
            if approve_optional_badge_failure:
                require(r['bundle'] is not None and follower_window_status(r['bundle'],int(self.clock()))in('closing','expired'),
                    'follower-recovery-not-applicable')
            self._save(box,r)
            if r['last_attempt'] is not None:
                # An uncertain attempt is checked/restored, never submitted anew.
                return self._check_locked(box,r,force=True)
            r['status']=super()._canonical(r)
            if r['status']['state']=='not-indexed':
                self._validate_for_submission(r)
                if not approve_optional_badge_failure:self._follower_submission_window(r)
                require(callable(getattr(self.relay,'submit_bundle',None)),'index-first-relay-required')
            r['last_attempt']={'requested_at':int(self.clock())};self._write('outbox.json',box)
            if r['status']['state']=='not-indexed':
                h=sha(encode(r['bundle']))
                reply=self.relay.submit_bundle(h,encode(r['bundle']))
                require(type(reply) is dict and set(reply)=={'transaction_hash'},'v5-relay-reply');hash32(reply['transaction_hash'])
                r['last_attempt']['transaction_hash']=reply['transaction_hash'];r['phase']='submitted'
                self._write('outbox.json',box)
            return self._check_locked(box,r,force=True)
