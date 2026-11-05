"""Parent-only deferred credential acquisition over the existing boot protocol.

Reuses the measured image's unchanged nonce/quote binding and pinned TLS rules.
The internal callback runs only after genuine enrollment and TLS possession;
no bootstrap data is returned, retried, logged or written to a credential file.
"""
import hashlib
import time

from boot_attestation import negotiate,PROFILE,INIT_FAILURE_CODES
from domain_transport import _timeout,send,receive
from domain_trust import pinned_channel_context,HOSTNAME
from policy import Rejected,canonical,require
REPORTABLE_BOOT_ERRORS=frozenset('enclave-startup:'+code for code in INIT_FAILURE_CODES)


def provision_boot_lazy(raw,approved,prepare):
    secure=None
    try:
        certificate,binding=negotiate(raw,approved);deadline=time.monotonic()+180
        _timeout(raw,deadline)
        secure=pinned_channel_context(certificate).wrap_socket(raw,server_hostname=HOSTNAME)
        require(secure.version()=='TLSv1.3' and secure.getpeercert(binary_form=True)==certificate,'parent-boot-channel')
        envelope=prepare()
        send(secure,{'binding_sha256':hashlib.sha256(canonical(binding)).hexdigest(),'bootstrap':envelope},65536,deadline)
        result=receive(secure,256,deadline)
        if (type(result) is dict and set(result)=={'profile','status','verified','code'}
                and result['profile']==PROFILE and result['status']=='unavailable' and result['verified'] is False
                and type(result['code']) is str and result['code'] in INIT_FAILURE_CODES):
            raise Rejected('enclave-startup:'+result['code'])
        require(result=={'profile':PROFILE,'status':'ready','verified':False},'parent-boot-not-ready')
    except Rejected as error:
        if len(error.args)==1 and type(error.args[0]) is str and error.args[0] in REPORTABLE_BOOT_ERRORS:raise
        raise Rejected('parent-boot-rejected') from None
    except Exception:raise Rejected('parent-boot-rejected') from None
    finally:
        if secure is not None:secure.close()
        raw.close()
