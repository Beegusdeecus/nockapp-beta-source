"""Fresh AWS-bound boot channel, distinct from credential-issuer enrollment.

The quote authorizes only a measured startup/secret-loading connection. It does
not assert a loaded signer, current registry, source observation or app identity.
"""
import base64
import hashlib
import secrets
import time

from domain_transport import channel_identity,send,receive,_decode,_timeout
from domain_trust import certificate_key,validate_approval,validate_pcrs,pinned_channel_context,HOSTNAME
from policy import POLICY_HASH,SOURCE,Rejected,canonical,hex_string,require
from trust import verify_aws_document

PROFILE='nockapp-zkid-issuer-boot-attestation-v1'
# Fixed public rejection labels extracted from the source-pinned serving image.
# No error message, formatted value or record-derived string is reportable.
PUBLIC_INIT_REJECTIONS=frozenset("""
abi-words account-already-active account-handle account-or-post-id action-challenge action-expired action-not-
outstanding action-record action-replay api-spending-limit authority-config authority-roles-must-differ
authorization-schema authorization-word aws-access-denied aws-credentials-expired aws-endpoint aws-expired-
session aws-http-ambiguous aws-http-content-type aws-http-encoding aws-http-status aws-invalid-ciphertext aws-
operation-forbidden aws-request-size aws-response-size aws-sdk-changed aws-sdk-duplicate aws-sdk-extra aws-
sdk-path aws-sdk-unapproved-import aws-sdk-wheel aws-sdk-wheel-missing aws-sdk-wheel-path aws-sdk-wheel-size
aws-sdk-wheel-type aws-tls-required aws-unavailable base-chain-identity base-contract-config base-contract-
identity base-journal-address base-journal-chunks base-journal-head base-journal-revision base-journal-size
base-rpc-budget base-rpc-clock base-rpc-endpoint base-rpc-http base-rpc-method base-rpc-proxy base-rpc-rate-
limit base-rpc-relay-host base-rpc-request-size base-rpc-response base-rpc-tls-context base-storage-conflict
base-storage-digest base-storage-missing base-storage-namespace base-storage-response base-storage-size base-
storage-table base-storage-unavailable base-vault-attestation base-vault-context base-vault-envelope base-
vault-key base-vault-response base-vault-size base-vault-unavailable base-vault-wrapped batch-size boot-
already-started boot-not-started bounded-issuer-anchor-changed bounded-issuer-block bounded-issuer-use-
indexed-record-for-ordering budget-directory budget-file budget-item budget-operation budget-request-already-
used budget-upgrade-chain budget-upgrade-context-pin budget-upgrade-contracts budget-upgrade-decrease budget-
upgrade-fee-policy budget-upgrade-limits budget-upgrade-no-change budget-upgrade-per-transaction-limit budget-
upgrade-plan budget-upgrade-review-pin channel-certificate consent-required count-application count-binary-
changed count-blind-request count-chain count-context count-contract count-demo-claims count-facts count-
identity-substitution count-input-size count-key-continuity count-legacy-view count-native-rejected count-
native-result count-native-unavailable count-proof-rejected count-proof-shape count-provider-required count-
publication-facts count-publication-profile count-receipt-context count-request-substitution count-session-
binding count-session-version count-state-authentication count-state-profile count-state-resume-only count-
verifier-unavailable credential-expired-or-invalid crypto-binary-changed crypto-input-size crypto-rejected
crypto-unavailable discovery-clock discovery-failed discovery-limit discovery-recovery-required discovery-
state domain-binary-changed domain-blind-request domain-identity-substitution domain-input-size domain-issuer-
changed domain-native-rejected domain-native-result domain-native-unavailable domain-proof-rejected domain-
receipt-context domain-request-substitution domain-state-authentication domain-state-capacity domain-state-
configuration domain-state-issuer domain-state-operation domain-state-profile event-data fact-unavailable
finality-rollback finality-unavailable finality-violation fixed-issuer-template follower-threshold identity-
ceremony-authority identity-ceremony-commit-conflict identity-ceremony-commit-unavailable identity-ceremony-
head identity-ceremony-key-mismatch identity-ceremony-missing identity-ceremony-purpose index-application
index-chain index-checkpoint-store-regression index-code-pin index-code-pin-required index-contract index-
event index-event-missing index-finality-unavailable index-finality-violation index-finalized-reorg index-hash
index-inclusion index-number index-page-limit index-record issuance-replay issuance-replay-or-substitution
issuer-attestation-rejected issuer-authority issuer-binding-profile issuer-boot-binding issuer-boot-channel
issuer-boot-config issuer-boot-envelope issuer-boot-hello issuer-boot-not-ready issuer-boot-quote issuer-boot-
rejected issuer-bootstrap issuer-bootstrap-unavailable issuer-channel-binding issuer-channel-certificate
issuer-channel-closed issuer-channel-timeout issuer-channel-unavailable issuer-code-identity issuer-debug-
device issuer-definition issuer-device issuer-document issuer-endpoint issuer-endpoint-address issuer-
endpoint-unavailable issuer-envelope issuer-finality-violation issuer-frame-size issuer-hello issuer-lease
issuer-lease-superseded issuer-listener issuer-not-approved issuer-not-ready issuer-pcr-approval issuer-
private-process issuer-public-state issuer-quote-binding issuer-quote-key issuer-quote-nonce issuer-quote-
stale issuer-registry issuer-relay issuer-relay-unavailable issuer-response issuer-result-size issuer-revoked
key-context key-record message-schema nsm-binary-changed nsm-binding nsm-document nsm-source-archive nsm-
source-archive-missing nsm-source-changed nsm-source-duplicate nsm-source-extra nsm-source-path nsm-source-
size nsm-source-type nsm-unavailable ordinary-post policy-upgrade-active-state post-application post-archive
post-audience post-context post-domain post-expired post-facts post-identity-disclosure post-not-accepted
post-proof-changed post-proof-conflict post-proof-shape post-proof-size post-receipt post-receipt-required
post-schema presentation-attributes presentation-challenge presentation-disclosure presentation-fact-false
presentation-facts presentation-policy presentation-profile presentation-schema presentation-time production-
trust-required provider-budget-required provider-factory provider-http-error provider-key-format provider-
path-forbidden provider-rate-limit provider-unavailable provision-ciphertext provision-context provision-
document provision-key provision-kind provision-recipient provision-response provision-runtime provision-value
provisioning-unavailable public-issuer-address public-issuer-anchor public-issuer-anchor-changed public-
issuer-chain public-issuer-code public-issuer-deployment public-issuer-event public-issuer-event-missing
public-issuer-fixed-authority public-issuer-head public-issuer-head-binding public-issuer-inclusion public-
issuer-index-event public-issuer-index-receipt public-issuer-log-limit public-issuer-public-view public-
issuer-search-limit public-issuer-size public-issuer-time public-issuer-uninitialized public-renewal-authority
public-renewal-batch public-renewal-bootstrap public-renewal-bootstrap-unavailable public-renewal-code public-
renewal-config public-renewal-context public-renewal-identities public-renewal-key-object public-renewal-
limits public-renewal-native public-renewal-private-process public-renewal-secrets public-renewal-selected-
updater publication-canonical publication-clock publication-content publication-context publication-event
publication-facts publication-number publication-orphaned publication-pending publication-post publication-
proof publication-receipt publication-registry publication-size publication-submission publication-time
receipt-key receipt-key-mismatch receipt-signer registration-already-committed registration-delivery-
unavailable registration-not-found registration-not-pending registration-unavailable registry-authentication
registry-capacity registry-conflict registry-directory registry-envelope registry-file registry-hash registry-
head registry-item registry-missing registry-namespace registry-number registry-profile registry-public
registry-public-projection registry-response registry-revision registry-state-changed registry-table registry-
table-arn registry-unavailable renewable-authority renewable-bootstrap renewable-bootstrap-unavailable
renewable-code renewable-identity renewable-issuer-config renewable-private-process renewable-root renewable-
workload renewable-workloads renewal-approval renewal-attestation-rejected renewal-binary-changed renewal-
blind-request renewal-boot-batch renewal-channel-certificate renewal-channel-confirmation renewal-channel-pin
renewal-channel-reply renewal-channel-unavailable renewal-document renewal-envelope renewal-hello renewal-
input-size renewal-issuer-definition renewal-issuer-view renewal-key-continuity renewal-native-rejected
renewal-native-result renewal-native-unavailable renewal-provider-required renewal-quote-binding renewal-
quote-stale renewal-registry renewal-request renewal-result-size renewal-service-address renewal-service-
anchor renewal-service-application renewal-service-chain renewal-service-chain-binding renewal-service-code
renewal-service-contracts renewal-service-fixed-code renewal-service-identity renewal-service-native renewal-
service-pin renewal-service-provider renewal-service-queue renewal-service-reorg renewal-service-state
renewal-service-state-view renewal-session renewal-session-binding renewal-session-version renewal-source-
binding renewal-state-authentication renewal-state-profile renewal-state-resume-only renewal-time replacement-
not-pending replacement-raced replica-config replica-conflict replica-digest replica-file replica-path
request-encoding request-scheme reserved-batch-exhausted runtime-file-changed runtime-manifest runtime-path
session-expired signed-rpc-config signed-rpc-method signed-rpc-sender source-account-mismatch source-account-
unavailable source-challenge-mismatch source-content-type source-discovery-schema source-duplicate-key source-
encoding source-error source-follower-count source-handle-mismatch source-http-ambiguous source-json source-
json-limits source-original-post-required source-post-count source-post-mismatch source-post-time source-
profile-object source-profile-type source-response-size source-schema source-stale-post source-tls-required
source-truncated source-user-schema source-user-status startup-authentication-rejected startup-unavailable
state-key submission-id timestamp transaction-chain transaction-contract-code transaction-contracts
transaction-count-budget transaction-creation transaction-creation-protection transaction-creations
transaction-execution-budget transaction-extra-fee-cap transaction-fee-cap transaction-fee-chain transaction-
fee-code transaction-fee-fork transaction-fee-head transaction-fee-head-stale transaction-fee-implementation
transaction-fee-journal-gap transaction-fee-receipt transaction-fee-recovery-pending transaction-fee-reorg
transaction-fee-request transaction-fee-response transaction-finality-unavailable transaction-finality-
violation transaction-funded-balance transaction-funded-cap transaction-funded-reorg transaction-funded-stale
transaction-funded-state transaction-gas transaction-gas-estimate transaction-hex transaction-initial-nonce
transaction-integer transaction-journal-authentication transaction-journal-context transaction-journal-create
transaction-journal-directory transaction-journal-envelope transaction-journal-file transaction-journal-gap
transaction-journal-missing transaction-journal-path transaction-journal-revision transaction-journal-rollback
transaction-journal-scratch-exists transaction-journal-size transaction-journal-tamper transaction-key
transaction-key-chain transaction-key-context transaction-key-mismatch transaction-key-record transaction-key-
updater transaction-laboratory-config transaction-limits transaction-nonce-conflict transaction-orphaned
transaction-receipt transaction-recovery-limit transaction-returned-hash transaction-rlp transaction-selectors
transaction-signature transaction-submission transaction-submission-conflict transaction-target transaction-
total-fee-budget transaction-total-fee-cap transaction-total-fee-overrun transaction-total-fee-policy
transaction-unknown updater-key-approval updater-key-authority updater-key-canonical updater-key-chain
updater-key-commit-conflict updater-key-commit-unavailable updater-key-document updater-key-head updater-key-
mismatch updater-key-offer updater-key-offer-rejected updater-key-public updater-key-quote updater-key-read
updater-key-record updater-key-scalar updater-key-scope updater-key-seed updater-key-selection-changed
updater-key-selection-missing updater-key-table updater-selection-address updater-selection-proposal updater-
selection-public workload-authorization-rejected workload-bootstrap-already-attempted workload-bootstrap-
approval workload-bootstrap-code workload-bootstrap-context workload-bootstrap-csr workload-bootstrap-document
workload-bootstrap-key workload-bootstrap-offer workload-bootstrap-offer-rejected workload-bootstrap-quote
workload-bootstrap-response workload-bootstrap-unavailable workload-ca-already-attempted workload-ca-authority
workload-ca-certificate-commit-conflict workload-ca-certificate-commit-unavailable workload-ca-certificate-
head workload-ca-certificate-identity workload-ca-certificate-missing workload-ca-certificate-revision
workload-ca-certificate-revision-conflict workload-ca-certificate-root workload-ca-commit-conflict workload-
ca-commit-unavailable workload-ca-device workload-ca-expiring workload-ca-head workload-ca-material workload-
ca-missing workload-ca-purpose workload-ca-scope workload-cert-bytes workload-cert-dates workload-cert-expired
workload-cert-extensions workload-cert-leaf workload-cert-profile workload-cert-purpose workload-cert-root
workload-cert-subject workload-certificate workload-config workload-credentials-unavailable workload-identity-
expired workload-identity-unavailable workload-key workload-renewal-ca workload-renewal-certificate workload-
renewal-creation-forbidden workload-renewal-identities workload-renewal-lifetime workload-renewal-purpose
workload-renewal-root-changed workload-renewal-selection-changed workload-renewal-selection-missing workload-
renewal-source workload-renewal-sources workload-restart-binding workload-restart-head workload-restart-pin
workload-restart-renewal-unconfirmed workload-restart-rollback workload-restart-root workload-restart-source
workload-role workload-root workload-seed workload-session-response workload-session-source workload-session-
unavailable workload-subject workload-tls workload-wrapped-seed wrapped-key
""".split())
PUBLIC_INIT_REJECTIONS=PUBLIC_INIT_REJECTIONS | frozenset(('issuer-handle-pool-state',
    'issuer-handle-pool-limit','issuer-handle-generation','issuer-boot-pool-exhausted','issuer-state-capacity'))
INIT_COMPONENTS=frozenset(('unknown','runtime','identity','sessions','issuer','updater','budget','journal','rpc','aws','state','tls'))
INIT_CLASSES=frozenset(('rejected','attribute','type','key','value','os','sqlite','other'))
INIT_FAILURE_CODES=PUBLIC_INIT_REJECTIONS | frozenset(
    'startup-'+component+'-'+kind for component in INIT_COMPONENTS for kind in INIT_CLASSES)
INIT_FILES={
    'public_renewal_runtime_v1.py':'runtime','workload_bootstrap.py':'identity',
    'workload_restart.py':'sessions','workload_sessions.py':'sessions','workload_renewal.py':'sessions',
    'workload_certificates.py':'sessions','workload_ca.py':'sessions',
    'provisioning.py':'issuer','public_updater_keys_v1.py':'updater','base_key_vault.py':'updater',
    'domain_authority.py':'budget','base_transactions.py':'journal','base_budget_upgrade_v1.py':'journal',
    'base_managed_storage.py':'journal','base_rpc.py':'rpc','base_fees.py':'rpc','aws_transport.py':'aws',
    'public_renewal_service_v1.py':'state','renewal_service_v3.py':'state','renewal_state_v3.py':'state',
    'issuer_supervisor.py':'tls'}


def initialization_failure_category(error):
    """Public code component/type only; never frame locals or traceback text."""
    kind=('rejected' if isinstance(error,Rejected) else
          'attribute' if isinstance(error,AttributeError) else
          'type' if isinstance(error,TypeError) else
          'key' if isinstance(error,KeyError) else
          'value' if isinstance(error,ValueError) else
          'os' if isinstance(error,OSError) else
          'sqlite' if type(error).__module__=='sqlite3' else 'other')
    component='unknown';frame=error.__traceback__
    for _ in range(64):
        if frame is None:break
        name=frame.tb_frame.f_code.co_filename.rsplit('/',1)[-1]
        if name in INIT_FILES:component=INIT_FILES[name]
        frame=frame.tb_next
    return 'startup-'+component+'-'+kind


def initialization_failure_code(error):
    """Only public constants; never send exception text, records or key material."""
    from cryptography.exceptions import InvalidTag
    from aws_transport import AwsFailure
    candidate='startup-unavailable';fallback=initialization_failure_category(error);seen=set()
    for _ in range(8):
        if not isinstance(error,BaseException) or id(error) in seen:break
        seen.add(id(error))
        if isinstance(error,InvalidTag):return 'startup-authentication-rejected'
        if type(error) is AwsFailure:
            value=error.response['Error']['Code']
            return {'AccessDeniedException':'aws-access-denied','ExpiredTokenException':'aws-expired-session',
                'InvalidCiphertextException':'aws-invalid-ciphertext'}.get(value,'aws-unavailable')
        if isinstance(error,Rejected) and len(error.args)==1 and type(error.args[0]) is str:
            if error.args[0] in INIT_FAILURE_CODES and candidate=='startup-unavailable':candidate=error.args[0]
        error=error.__cause__ if error.__cause__ is not None else error.__context__
    return fallback if candidate=='startup-unavailable' else candidate


def binding(certificate,identity,authority,namespace):
    for value in (identity,authority,namespace):hex_string(value,64)
    return {'profile':PROFILE,'code_identity':identity,'state_authority_sha256':authority,
            'definition_hash':namespace,'policy':POLICY_HASH,'source':SOURCE,
            'certificate_sha256':hashlib.sha256(certificate).hexdigest()}


def negotiate(raw,approved):
    validate_approval(approved);nonce=secrets.token_hex(32);deadline=time.monotonic()+30
    send(raw,{'profile':PROFILE,'nonce':nonce},256,deadline)
    envelope=receive(raw,65536,deadline)
    require(type(envelope) is dict and set(envelope)=={'profile','certificate','document'}
            and envelope['profile']==PROFILE,'issuer-boot-envelope')
    cert=_decode(envelope['certificate'],8192)
    expected=binding(cert,approved['code_identity'],approved['state_authority_sha256'],approved['definition_hash'])
    now=int(time.time()*1000);payload=verify_aws_document(_decode(envelope['document'],32768),now)
    require(payload.get('nonce')==bytes.fromhex(nonce) and payload.get('public_key')==certificate_key(cert)
            and payload.get('user_data')==hashlib.sha256(canonical(expected)).digest()
            and type(payload.get('timestamp')) is int and now-120000<=payload['timestamp']<=now+5000,'issuer-boot-quote')
    validate_pcrs(payload['pcrs'],approved['pcrs'])
    return cert,expected


def inspect_boot(raw,approved):
    try:
        _,bind=negotiate(raw,approved)
        return {'profile':PROFILE,'binding':bind,'hardware_verified':True,'issuer_loaded':False,
                'verified':False,'production_ready':False}
    except Exception:raise Rejected('issuer-boot-rejected') from None
    finally:raw.close()


def provision_boot(raw,envelope,approved):
    secure=None
    try:
        cert,bind=negotiate(raw,approved);deadline=time.monotonic()+180
        _timeout(raw,deadline)
        secure=pinned_channel_context(cert).wrap_socket(raw,server_hostname=HOSTNAME)
        require(secure.version()=='TLSv1.3' and secure.getpeercert(binary_form=True)==cert,'issuer-boot-channel')
        send(secure,{'binding_sha256':hashlib.sha256(canonical(bind)).hexdigest(),'bootstrap':envelope},65536,deadline)
        result=receive(secure,256,deadline)
        require(result=={'profile':PROFILE,'status':'ready','verified':False},'issuer-boot-not-ready')
        return result
    except Exception:raise Rejected('issuer-boot-rejected') from None
    finally:
        if secure is not None:secure.close()
        raw.close()


def serve_boot(raw,nsm,identity,authority,namespace,handler):
    secure=None;handler_started=False
    try:
        deadline=time.monotonic()+180;hello=receive(raw,256,deadline)
        require(type(hello) is dict and set(hello)=={'profile','nonce'} and hello['profile']==PROFILE,'issuer-boot-hello')
        hex_string(hello['nonce'],64);context,cert=channel_identity();bind=binding(cert,identity,authority,namespace)
        document=nsm.attest(bytes.fromhex(hello['nonce']),certificate_key(cert),hashlib.sha256(canonical(bind)).digest())
        send(raw,{'profile':PROFILE,'certificate':base64.b64encode(cert).decode(),
                  'document':base64.b64encode(document).decode()},65536,deadline)
        _timeout(raw,deadline);secure=context.wrap_socket(raw,server_side=True)
        request=receive(secure,65536,deadline)
        require(type(request) is dict and set(request)=={'binding_sha256','bootstrap'}
                and request['binding_sha256']==hashlib.sha256(canonical(bind)).hexdigest(),'issuer-boot-binding')
        handler_started=True;result=handler(request['bootstrap'])
        send(secure,{'profile':PROFILE,'status':'ready','verified':False},256,deadline)
        return result
    except Exception as error:
        # Report only after bound TLS and the exact boot envelope were admitted.
        # This is an unsuccessful startup, never loaded-issuer attestation or a
        # retry authorization. All original caller/delivery fences still apply.
        if secure is not None and handler_started:
            try:send(secure,{'profile':PROFILE,'status':'unavailable','verified':False,
                'code':initialization_failure_code(error)},256,deadline)
            except Exception:pass
        return None
    finally:
        if secure is not None:secure.close()
        raw.close()
