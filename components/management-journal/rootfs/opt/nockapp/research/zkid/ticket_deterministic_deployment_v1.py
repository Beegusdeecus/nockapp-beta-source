"""Public CREATE2 plans for fixed ticket contracts before service-key sealing.

No wallet identity/nonce, keys, signatures, funding, deployment, source query or
permission change. Uses the existing factory only after exact runtime-code pin
checking. Chain reads remain dependent on the configured RPC.
"""
import copy
import hashlib
import json
from pathlib import Path
import subprocess

from base_evm import TOOLS, encode
from base_protocol import keccak
from permissionless_contracts import SETTINGS
from policy import digest, hex_string, require
from ticket_offer_v1 import terms, terms_hash, manifest_hash, hex_value, OFFER_V2
from ticket_refund_vault_v1 import SCOPE, scope_manifest

ROOT = Path(__file__).resolve().parent
FACTORY = '0x4e59b44847b379578588920ca78fbf26c0b4956c'
FACTORY_RUNTIME = bytes.fromhex('7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3')
FACTORY_SHA = 'e0af82ad2e5188285db8ba0b2ae054d13f0fd4fe325c48c7f2dace48454404b9'
SOURCE_URL = 'https://github.com/Arachnid/deterministic-deployment-proxy/blob/99f24d0e09d8fad7ddb5cd37333e92a8956c9783/source/deterministic-deployment-proxy.yul'
PROFILE = 'nockapp-ticket-deterministic-deployment-plan-v1'


def compile_contract(name):
    require(name in ('PrepaidTicketPacks', 'PrepaidRefundVault'), 'ticket-deployment-contract')
    source = 'contracts/' + name + '.sol'
    settings = copy.deepcopy(SETTINGS)
    settings['outputSelection']['*'][''] = ['ast']
    body = (ROOT / 'base' / source).read_text()
    request = {'language': 'Solidity', 'sources': {source: {'content': body}}, 'settings': settings}
    done = subprocess.run([str(TOOLS / 'solc-0.8.30'), '--standard-json'], input=json.dumps(request).encode(),
                          capture_output=True, timeout=30, check=True)
    output = json.loads(done.stdout)
    require(not any(item['severity'] == 'error' for item in output.get('errors', [])), 'ticket-deployment-compile')
    return output['contracts'][source][name], output['sources'][source]['ast'], hashlib.sha256(body.encode()).hexdigest()


def runtime(compiled, ast, values):
    names = {}
    def walk(value):
        if isinstance(value, dict):
            if value.get('nodeType') == 'VariableDeclaration' and value.get('mutability') == 'immutable':
                names[str(value['id'])] = value['name']
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(ast)
    template = compiled['evm']['deployedBytecode']
    refs = template['immutableReferences']
    require(set(refs) <= set(names) and {names[key] for key in refs} == set(values), 'ticket-deployment-immutables')
    code = bytearray.fromhex(template['object'])
    offsets = set()
    for key, ranges in refs.items():
        value = values[names[key]]
        require(type(value) is int and 0 <= value < 2**256, 'ticket-deployment-immutable-value')
        for where in ranges:
            offset = where['start']
            require(where['length'] == 32 and type(offset) is int and 0 <= offset <= len(code) - 32
                and not offsets.intersection(range(offset, offset + 32)) and code[offset:offset + 32] == b'\0' * 32,
                'ticket-deployment-immutable-offset')
            offsets.update(range(offset, offset + 32))
            code[offset:offset + 32] = value.to_bytes(32, 'big')
    return bytes(code)


def address(salt, initcode):
    hex_string(salt, 64)
    require(type(initcode) is bytes and 0 < len(initcode) <= 49152, 'ticket-deployment-initcode')
    return '0x' + keccak(b'\xff' + bytes.fromhex(FACTORY[2:]) + bytes.fromhex(salt)
                         + bytes.fromhex(keccak(initcode)[2:]))[-40:]


def build(offer_terms, refund_authority, max_refunds, generated_public_sha256):
    offer_terms = copy.deepcopy(terms(offer_terms))
    require(offer_terms['profile'] == OFFER_V2, 'ticket-deployment-offer-version')
    hex_value(refund_authority, 20)
    hex_string(generated_public_sha256, 64)
    require(any(bytes.fromhex(generated_public_sha256)) and type(max_refunds) is int
            and 1 <= max_refunds <= 4096, 'ticket-deployment-public-review')
    purchase, purchase_ast, purchase_source = compile_contract('PrepaidTicketPacks')
    hashed_terms = terms_hash(offer_terms)
    purchase_init = bytes.fromhex(purchase['evm']['bytecode']['object'] + encode('f(bytes32,address,uint256,uint64)',
        hashed_terms, offer_terms['payment_recipient'], offer_terms['pack_price_wei'], offer_terms['purchase_before'])[10:])
    purchase_code = runtime(purchase, purchase_ast, {'termsHash': int(hashed_terms, 16),
        'recipient': int(offer_terms['payment_recipient'], 16), 'packPrice': int(offer_terms['pack_price_wei']),
        'purchaseBefore': offer_terms['purchase_before']})
    common = {'profile': PROFILE, 'chain_id': 84532, 'application': offer_terms['application'],
              'generated_public_sha256': generated_public_sha256, 'terms_sha256': hashed_terms}
    purchase_salt = digest({**common, 'role': 'purchase'})
    purchase_address = address(purchase_salt, purchase_init)
    manifest = {'terms': offer_terms, 'purchase_contract': purchase_address, 'purchase_runtime_keccak': keccak(purchase_code)}
    offer_hash = manifest_hash(manifest)
    refund, refund_ast, refund_source = compile_contract('PrepaidRefundVault')
    price = int(offer_terms['pack_price_wei'])
    refund_init = bytes.fromhex(refund['evm']['bytecode']['object'] + encode('f(bytes32,address,address,uint256,uint256)',
        '0x' + offer_hash, purchase_address, refund_authority, price, max_refunds)[10:])
    refund_code = runtime(refund, refund_ast, {'parameters': int(offer_hash, 16), 'purchaseContract': int(purchase_address, 16),
        'authority': int(refund_authority, 16), 'packPrice': price, 'maxRefunds': max_refunds, 'principalBudget': price * max_refunds})
    refund_salt = digest({**common, 'role': 'refund', 'offer_sha256': offer_hash, 'authority': refund_authority,
                          'max_refunds': max_refunds})
    refund_address = address(refund_salt, refund_init)
    scope = {'profile': SCOPE, 'parameters': offer_hash, 'chain_id': 84532, 'vault': refund_address,
        'runtime_sha256': hashlib.sha256(refund_code).hexdigest(), 'authority': refund_authority,
        'pack_price_wei': str(price), 'max_refunds': max_refunds, 'principal_budget_wei': str(price * max_refunds), 'gas': 200000}
    scope_manifest(scope, manifest, offer_hash, digest(scope))
    contracts = {}
    for role, salt, init, deployed, code in (
        ('purchase', purchase_salt, purchase_init, purchase_address, purchase_code),
        ('refund', refund_salt, refund_init, refund_address, refund_code)):
        contracts[role] = {'address': deployed, 'salt': salt, 'initcode_sha256': hashlib.sha256(init).hexdigest(),
            'runtime_sha256': hashlib.sha256(code).hexdigest(), 'runtime_keccak': keccak(code),
            'transaction': {'chainId': '0x14a34', 'to': FACTORY, 'value': '0x0', 'data': '0x' + salt + init.hex()}}
    return {'profile': PROFILE, 'factory': FACTORY, 'factory_runtime_sha256': FACTORY_SHA,
        'factory_source': SOURCE_URL, 'offer': manifest, 'offer_sha256': offer_hash, 'refund_vault': scope,
        'refund_vault_sha256': digest(scope), 'contracts': contracts, 'funding_or_deployment_performed': False,
        'compiler_sha256': hashlib.sha256((TOOLS / 'solc-0.8.30').read_bytes()).hexdigest(),
        'contract_sources_sha256': {'PrepaidTicketPacks.sol': purchase_source, 'PrepaidRefundVault.sol': refund_source}}


def inspect(rpc, plan, expected_sha256):
    require(type(plan) is dict and plan.get('profile') == PROFILE and plan.get('factory') == FACTORY
        and plan.get('factory_runtime_sha256') == FACTORY_SHA and digest(plan) == expected_sha256,
        'ticket-deployment-plan')
    require(int(rpc.call('eth_chainId'), 16) == 84532, 'ticket-deployment-chain')
    final = rpc.call('eth_getBlockByNumber', 'finalized', False)
    raw = bytes.fromhex(rpc.call('eth_getCode', FACTORY, final['number'])[2:])
    require(raw == FACTORY_RUNTIME and hashlib.sha256(raw).hexdigest() == FACTORY_SHA, 'ticket-deployment-factory-code')
    states = {}
    for role, item in plan['contracts'].items():
        tx = item['transaction']
        require(tx['chainId'] == '0x14a34' and tx['to'] == FACTORY and tx['value'] == '0x0'
            and tx['data'].startswith('0x' + item['salt']), 'ticket-deployment-transaction')
        init = bytes.fromhex(tx['data'][66:])
        require(hashlib.sha256(init).hexdigest() == item['initcode_sha256']
            and address(item['salt'], init) == item['address'], 'ticket-deployment-address')
        code = bytes.fromhex(rpc.call('eth_getCode', item['address'], final['number'])[2:])
        require(not code or hashlib.sha256(code).hexdigest() == item['runtime_sha256'], 'ticket-deployment-existing-code')
        states[role] = 'absent' if not code else 'exact-runtime-already-deployed'
    require(rpc.call('eth_getBlockByNumber', final['number'], False)['hash'] == final['hash'], 'ticket-deployment-finality-reorg')
    return {'profile': PROFILE, 'ok': True, 'factory_verified': True, 'states': states,
            'finalized_block': final['number'], 'RPC_trust_not_light_client': True, 'transaction_submitted': False}
