"""First journal setup for reviewed NEW, unfunded, sealed host service keys.

Trusted installation API, absent from worker/browser RPC. Chain nonce/balance
checks do not prove key freshness; the separately reviewed generation record
and sealed packet must belong to this exact first setup. No key generation,
funding, signing, broadcast, source-issuer state, budget initialization or reset.
"""
import hashlib

from cryptography.hazmat.primitives.asymmetric import ec
from base_protocol import ReceiptKey
from base_transactions import Limits, ProtectedSigner
from policy import canonical, digest, hex_string, require
from ticket_backend_boot_v1 import validate, harden_process, private_key
from ticket_backend_records_v1 import RoleRecords
from ticket_backend_resources_v1 import Resources, open_sealed
from ticket_journal_v2 import ImmutableS3JournalAnchor
from ticket_native_v1 import TicketNative
from ticket_offer_v1 import TicketOffer
from ticket_payment_v1 import FinalizedTicketPayment
from ticket_publication_queue_v2 import TicketPublicationQueue, PROFILE as LEDGER
from ticket_refund_payout_v1 import RefundQueue, namespace as refund_namespace

PROFILE = 'nockapp-ticket-first-journal-plan-v1'
PREDEPLOYMENT = 'nockapp-ticket-first-journal-before-contracts-v2'
PURPOSE = 'new-unfunded-host-service-authority'
GENERATED_PUBLIC = 'nockapp-ticket-generated-public-keys-v1'


def public_scope(backend, backend_pin, intent, intent_pin, generated):
    cfg = validate(backend, backend_pin)
    require(cfg['role'] in ('publication', 'refund'), 'first-journal-role')
    before_contracts = type(intent) is dict and intent.get('profile') == PREDEPLOYMENT
    require(type(intent) is dict and set(intent) == {'profile', 'purpose', 'role', 'backend_sha256',
        'resources_sha256', 'sealed_boot_sha256', 'generated_public_sha256', 'service_address'} |
        ({'predeployment_sha256'} if before_contracts else set())
        and intent['profile'] in (PROFILE, PREDEPLOYMENT) and intent['purpose'] == PURPOSE and digest(intent) == intent_pin,
        'first-journal-review')
    require(intent['role'] == cfg['role'] and intent['backend_sha256'] == backend_pin
        and intent['service_address'] == cfg['key_bindings'][cfg['role']], 'first-journal-binding')
    for field in ('resources_sha256', 'sealed_boot_sha256', 'generated_public_sha256'):
        hex_string(intent[field], 64)
        require(any(bytes.fromhex(intent[field])), 'first-journal-pin')
    if before_contracts:
        hex_string(intent['predeployment_sha256'], 64)
        require(any(bytes.fromhex(intent['predeployment_sha256'])), 'first-journal-pin')
    require(type(generated) is dict and generated.get('profile') == GENERATED_PUBLIC
        and digest(generated) == intent['generated_public_sha256']
        and set(generated) == {'profile', 'ticket_spki', 'key_bindings', 'tls'}
        and generated['key_bindings'] == cfg['key_bindings']
        and generated['ticket_spki'] == cfg['offer']['terms']['ticket_spki'], 'first-journal-generation-record')
    require(type(generated['tls']) is dict and set(generated['tls']) == {'payment', 'publication', 'refund'}
        and all(type(value) is dict and set(value) == {'hostname', 'key_sha256', 'csr_der'}
                for value in generated['tls'].values()), 'first-journal-generation-record')
    tls = generated['tls'].get(cfg['role'])
    require(type(tls) is dict and tls.get('hostname') == cfg['tls']['hostname']
        and tls.get('key_sha256') == cfg['tls']['key_sha256'], 'first-journal-generation-record')
    return cfg


def chain_zero(rpc, address, *, unfunded):
    require(int(rpc.call('eth_chainId'), 16) == 84532, 'first-journal-chain')
    block = rpc.call('eth_getBlockByNumber', 'latest', False)
    require(type(block) is dict and type(block.get('number')) is str and type(block.get('hash')) is str,
            'first-journal-chain-head')
    require(int(rpc.call('eth_getTransactionCount', address, block['number']), 16) == 0
        and int(rpc.call('eth_getTransactionCount', address, 'pending'), 16) == 0, 'first-journal-used-authority')
    if unfunded:
        require(int(rpc.call('eth_getBalance', address, block['number']), 16) == 0, 'first-journal-funded-authority')
    require(rpc.call('eth_getCode', address, block['number']) == '0x', 'first-journal-contract-authority')
    require(rpc.call('eth_getBlockByNumber', block['number'], False)['hash'] == block['hash'],
            'first-journal-chain-reorg')


class ReadOnlyAnchor(ImmutableS3JournalAnchor):
    def compare_exchange(self, *args, **kwargs):
        raise ValueError('first-journal-observer-cannot-write')


class ReadOnlyRPC:
    """Even accidental recovery cannot sign/broadcast during setup inspection."""
    def __init__(self, rpc):
        self.rpc = rpc
    def call(self, method, *args):
        require(method in {'eth_chainId', 'eth_getBlockByNumber', 'eth_getBlockByHash',
            'eth_getTransactionCount', 'eth_getBalance', 'eth_getCode', 'eth_call',
            'eth_getTransactionReceipt', 'eth_getTransactionByHash'}, 'first-journal-read-only-rpc')
        return self.rpc.call(method, *args)
    def check_identity(self, hashes):
        from base_rpc import BaseRPC
        return BaseRPC.check_identity(self, hashes)


def deployment_scope(cfg, intent, plan):
    """Explicit reviewed CREATE2 plan, never a claim that future code exists."""
    require(intent['profile'] == PREDEPLOYMENT and type(plan) is dict
        and digest(plan) == intent['predeployment_sha256']
        and plan.get('offer') == cfg['offer'] and plan.get('offer_sha256') == cfg['offer_sha256']
        and type(plan.get('contracts')) is dict and set(plan['contracts']) == {'purchase', 'refund'},
        'first-journal-predeployment-binding')
    purchase, refund = plan['contracts']['purchase'], plan['contracts']['refund']
    scope = plan.get('refund_vault')
    require(purchase['address'] == cfg['offer']['purchase_contract']
        and purchase['runtime_keccak'] == cfg['offer']['purchase_runtime_keccak']
        and type(scope) is dict and scope['authority'] == cfg['key_bindings']['refund']
        and scope['vault'] == refund['address'] and scope['runtime_sha256'] == refund['runtime_sha256']
        and scope['parameters'] == cfg['offer_sha256'], 'first-journal-predeployment-authorities')
    from ticket_refund_vault_v1 import scope_manifest
    scope_manifest(scope, cfg['offer'], cfg['offer_sha256'], plan['refund_vault_sha256'])
    if cfg['role'] == 'refund':
        require(scope == cfg['refund_vault'] and plan['refund_vault_sha256'] == cfg['refund_vault_sha256'],
                'first-journal-predeployment-authorities')
    return plan


class FirstSetupRPC(ReadOnlyRPC):
    """Only empty genesis creation may defer the exact planned vault's code.

    Normal workers never receive this adapter. Every real call goes to the RPC;
    no contract response/code is fabricated. Signing/broadcast remain disabled.
    """
    def __init__(self, rpc, plan):
        super().__init__(rpc)
        item = plan['contracts']['refund']
        self.future = {item['address']: item['runtime_sha256']}
        self.deferred = []

    def check_identity(self, hashes):
        for address, expected in hashes.items():
            if self.future.get(address) == expected and self.call('eth_getCode', address, 'latest') == '0x':
                self.deferred.append(address)
            else:
                super().check_identity({address: expected})


def run(backend, backend_pin, intent, intent_pin, generated, resources, envelope, *, ticket_native, scratch, observe=False,
        predeployment=None):
    """One explicit creation, or read-only resolution of an uncertain creation.

    The launcher must persist a no-retry intent BEFORE calling this function.
    Observation accepts only revision zero and an entirely empty journal.
    A funded/used service is never initialized; normal workers retain recovery.
    """
    cfg = public_scope(backend, backend_pin, intent, intent_pin, generated)
    if intent['profile'] == PREDEPLOYMENT:
        deployment_scope(cfg, intent, predeployment)
    else:
        require(predeployment is None, 'first-journal-unreviewed-predeployment')
    require(isinstance(ticket_native, TicketNative) and ticket_native.sha256 == cfg['ticket_native_sha256'],
            'first-journal-ticket-native')
    require(type(observe) is bool and type(resources) is Resources
        and resources.role == cfg['role'] and resources.backend_sha256 == backend_pin
        and resources.plan_sha256 == intent['resources_sha256']
        and resources.sealed_boot_sha256 == intent['sealed_boot_sha256']
        and type(envelope) is bytes and hashlib.sha256(envelope).hexdigest() == intent['sealed_boot_sha256'],
        'first-journal-resource-binding')
    harden_process()
    address = cfg['key_bindings'][cfg['role']]
    rpc = ReadOnlyRPC(resources.rpc)
    deployment_observation = None
    if predeployment is not None:
        from ticket_deterministic_deployment_v1 import inspect
        deployment_observation = inspect(rpc, predeployment, intent['predeployment_sha256'])
        rpc = FirstSetupRPC(resources.rpc, predeployment)
    chain_zero(rpc, address, unfunded=not observe)
    transaction = cfg['transaction']
    offer = TicketOffer(cfg['offer'], cfg['offer_sha256'], ticket_native)
    if predeployment is None:
        FinalizedTicketPayment(rpc, offer).preflight()
    ns = (hashlib.sha256(('84532:' + address + ':' + LEDGER).encode()).hexdigest()
          if cfg['role'] == 'publication' else refund_namespace(address))
    records = RoleRecords(resources.s3, cfg['records']['account_id'], {
        (cfg['records']['ledger_bucket'], 'ticket-publication-ledger-v2/' + ns + '/'): ('snapshot', True)})
    anchor_type = ReadOnlyAnchor if observe else ImmutableS3JournalAnchor
    anchor = anchor_type(records, cfg['records']['ledger_bucket'], ns, account_id=cfg['records']['account_id'])
    revision, _ = anchor.read()
    if observe and revision is None:
        return {'profile': intent['profile'], 'ok': True, 'role': cfg['role'], 'intent_sha256': intent_pin,
                'initialization_performed': False, 'read_only_observation': True, 'journal_exists': False,
                'managed_revision': None, 'service_keys_created': False, 'funding_or_signing_or_broadcast': False}
    require(revision == 0 if observe else revision is None, 'first-journal-existing-authority')
    # No KMS/private input before all public scope, chain and empty-slot checks.
    body = open_sealed(resources, envelope)
    require(set(body) == {'profile', 'role', 'config_sha256', 'service_key_der',
                         'tls_private_key_der', 'tls_certificate_der'}, 'first-journal-private-scope')
    _, key = private_key(body['service_key_der'])
    require(isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256K1),
            'first-journal-service-key')
    receipt = ReceiptKey(rpc, key)
    require(receipt.address == address, 'first-journal-service-key')
    signer = ProtectedSigner(rpc, receipt)
    # This operation has no reason to sign, even if a constructor regresses.
    def no_sign(*args, **kwargs):
        raise ValueError('first-journal-signing-forbidden')
    signer.sign = no_sign
    chain_zero(rpc, address, unfunded=not observe)
    arguments = {'anchor': anchor, 'fee_policy': transaction['fee_policy'],
                 **({} if observe else {'initial_nonce': 0})}
    from pathlib import Path
    path = Path(scratch) / 'first-journal.sqlite'
    if cfg['role'] == 'publication':
        queue = TicketPublicationQueue(rpc, signer, path, offer.terms['index_contract'], offer.terms['application'],
            Limits(**transaction['limits']), code_hashes={offer.terms['index_contract']: transaction['runtime_sha256']},
            **arguments)
        jobs = 'ticket_jobs'
    else:
        queue = RefundQueue(rpc, signer, path, offer, cfg['refund_vault'], Limits(**transaction['limits']),
            expected_hash=cfg['refund_vault_sha256'], **arguments)
        jobs = 'refund_jobs'
    with queue._db() as db:
        meta = queue._meta(db)
        require(meta['first_nonce'] == meta['next_nonce'] == 0
            and all(db.execute('SELECT count(*) FROM ' + table).fetchone()[0] == 0
                    for table in ('submissions', 'fees', jobs)), 'first-journal-not-empty')
    require(anchor.read()[0] == 0, 'first-journal-revision')
    return {'profile': intent['profile'], 'ok': True, 'role': cfg['role'], 'intent_sha256': intent_pin,
            'context_sha256': hashlib.sha256(queue.context.encode()).hexdigest(),
            'initialization_performed': not observe, 'read_only_observation': observe,
            'journal_exists': True,
            'first_nonce': 0, 'next_nonce': 0, 'managed_revision': 0,
            'service_keys_created': False, 'funding_or_signing_or_broadcast': False,
            **({'predeployment_observation': deployment_observation,
                'deferred_genesis_only_runtime_checks': list(rpc.deferred)} if predeployment is not None else {})}
