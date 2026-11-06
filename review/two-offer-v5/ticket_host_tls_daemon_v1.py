"""Separate fixed-policy host certificate renewal loop, trusted launcher API.

Existing public policy/root must be independently pinned. No root creation or
replacement, arbitrary CSR/job input, CA private key, ambient authentication,
permission changes or service installation. Dedicated renewable IAM/UID and
read-only service mounts remain enforced deployment requirements.
"""
import copy
import os
import threading
import time

from cryptography import x509
from policy import digest,require
from ticket_host_tls_ca_v1 import HostCA,ROLES,leaf_values,spki,sha
from ticket_host_tls_delivery_v1 import PublicCertificates,leaf

PROFILE='nockapp-host-tls-renewal-loop-v1'
ROOT_MAINTENANCE_SECONDS=14*86400


class CertificateRenewer:
    def __init__(self,authority,policy_pin,root_pin,directory,*,interval=300):
        require(type(authority) is HostCA and authority._root is not None
            and authority._record is not None and authority._pin==policy_pin
            and digest(authority._record)==root_pin,'host-tls-loop-authority')
        require(type(directory) is PublicCertificates and directory.owner_uid==os.getuid(),
            'host-tls-loop-writer')
        require(type(interval) is int and 30<=interval<=300,'host-tls-loop-interval')
        directory._same()
        self._authority=authority;self._policy_pin=policy_pin;self._root_pin=root_pin
        self._directory=directory;self.interval=interval;self._lock=threading.RLock()
        self._started=False;self._last=0;self._sequence=0
    def __repr__(self):return '<Fixed three-service TLS renewal loop; credentials omitted>'
    def __reduce_ex__(self,_):raise TypeError('host-tls-loop-serialization-forbidden')

    def _certificate(self,role,data,now):
        cert=leaf(data);authority=self._authority;policy=authority._policy
        csr=authority._csrs[role];hostname=policy['services'][role]['hostname']
        wanted=[(v.oid,critical,v.public_bytes()) for v,critical in leaf_values(hostname)]
        require(cert.subject==csr.subject and spki(cert.public_key())==spki(csr.public_key())
            and cert.signature_hash_algorithm.name=='sha256'
            and [(e.oid,e.critical,e.value.public_bytes()) for e in cert.extensions]==wanted
            and policy['root_not_before']<=cert.not_valid_before_utc.timestamp()<=now
            and now+60<cert.not_valid_after_utc.timestamp()<=policy['root_not_after']
            and cert.not_valid_after_utc.timestamp()-cert.not_valid_before_utc.timestamp()<=policy['leaf_seconds']+60,
            'host-tls-loop-leaf')
        cert.verify_directly_issued_by(authority._root)
        return int(cert.not_valid_after_utc.timestamp())

    def cycle(self,stop=None):
        """One bounded sweep; at most one fixed Sign attempt for each role.

        A failed/uncertain public write is inspected on the next cycle. A valid
        committed leaf suppresses another Sign, including after process restart.
        No operation is retried within a cycle. Later fixed-role renewal is safe
        because it changes public certificates, never service keys or funds.
        """
        require(stop is None or type(stop) is threading.Event,'host-tls-loop-stop')
        with self._lock:
            now=int(time.time());policy=self._authority._policy
            result={'profile':PROFILE,'sequence':self._sequence,'policy_sha256':self._policy_pin,
                'root_record_sha256':self._root_pin,'root_not_after':policy['root_not_after'],
                'root_maintenance_due':now>=policy['root_not_after']-ROOT_MAINTENANCE_SECONDS,
                'ok':False,'phase':'checking','issuance_attempts':[],'roles':{},'automatic_root_change':False}
            self._sequence+=1
            if stop is not None and stop.is_set():result['phase']='stopped';return result
            if now<self._last-5 or not policy['root_not_before']<=now<policy['root_not_after']-60:
                result.update(phase='clock-or-root-window-unavailable',root_maintenance_due=True);return result
            self._last=max(now,self._last)
            try:
                require(self._directory.owner_uid==os.getuid(),'host-tls-loop-writer')
                self._directory._same()
            except Exception:
                result['phase']='publication-directory-unavailable';return result
            for role in ROLES:
                if stop is not None and stop.is_set():result['phase']='stopped';return result
                try:
                    data=self._directory.read(role);expiry=self._certificate(role,data,now)
                except Exception:data=None;expiry=0
                if data is not None and expiry-now>policy['renew_before_seconds']:
                    result['roles'][role]={'state':'retained','certificate_sha256':sha(data),'expires_at':expiry}
                    continue
                previous_expiry=expiry
                try:
                    result['issuance_attempts'].append(role)
                    data=self._authority.issue(role);expiry=self._certificate(role,data,int(time.time()))
                    saved=self._directory.publish(role,data)
                    result['roles'][role]={'state':'renewed',**saved,'expires_at':expiry}
                except Exception:
                    result['roles'][role]={'state':'unavailable','code':'host-tls-renewal-unavailable',
                        'previous_leaf_expires_at':previous_expiry}
            result['ok']=all(v['state'] in ('retained','renewed') for v in result['roles'].values())
            result['phase']='ready' if result['ok'] else 'renewal-unavailable'
            return result

    def run(self,stop,emit):
        require(type(stop) is threading.Event and callable(emit),'host-tls-loop-run')
        with self._lock:
            require(not self._started,'host-tls-loop-started');self._started=True
        cycles=0
        while not stop.is_set():
            result=self.cycle(stop);emit(copy.deepcopy(result));cycles+=1
            # Fixed delay after completion also bounds failures, without retrying
            # the same AWS call or busy-looping. stop interrupts the wait.
            if stop.wait(self.interval):break
        return {'profile':PROFILE,'phase':'stopped','cycles':cycles,'automatic_root_change':False}
