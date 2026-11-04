"""Public X issuance context and strict component schemas; no private inputs.

Source trust and software approval are administrator configuration. A claimant
may propose only proof commitments/results under an already issued context.
"""
import hashlib
import json
import re

POLICY = 'nockapp-x-current-viewer-source-v2'
TICKET = 'nockapp-x-issuance-context-v1'
CONTEXT_DOMAIN = b'NOCKAPP/X/ISSUANCE-CONTEXT/v1\0'
HOLDER_DOMAIN = b'NOCKAPP/HOLDER/P256/v1\0'
PURPOSE = hashlib.sha256(b'NOCKAPP/X/PASSPORT-ISSUANCE/v1\0').hexdigest()
LIFETIME = 120
REQUEST_PROFILE = 'nockapp-x-viewer-private-request-binding-v1'
HTTP_PROFILE = 'nockapp-private-http-body-binding-v1'
JSON_PROFILE = 'nockapp-x-viewer-private-json-binding-v1'
NOCK_PROFILE = 'nockapp-private-native-application-v1'
PROGRAM_ID = '27b31d22cd242b44c8ee3445a4b0accd8de3099304755ca9ac8050031a57c407'
INNER_POLICY_ID = 'af679240f77468b985565d12d658b7e7fec7cb2f2b37fc92b49fba806bf3c76f'
TARGET = '/graphql/ZXYoRV2xxqxwt4hUF3IzQg/viewerQuery?variables=%7B%22__relay_internal__pv__xclientsfeaturesappviewerisloggedinrelayprovider%22%3Atrue%7D'
PROFILES = {'request_profile': REQUEST_PROFILE, 'http_profile': HTTP_PROFILE,
            'json_profile': JSON_PROFILE, 'nock_profile': NOCK_PROFILE,
            'target': TARGET, 'max_sent': 4096, 'max_received': 8192}


def require(condition):
    if not condition:
        raise ValueError('invalid X policy or public context')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def loads(data):
    require(type(data) in (str, bytes) and len(data) <= 2_000_000)
    return json.loads(data, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid JSON')))


def hex_value(value, size=32, *, nonzero=False):
    require(type(value) is str and re.fullmatch('[0-9a-f]{' + str(2 * size) + '}', value) is not None)
    require(not nonzero or value != '00' * size)
    return bytes.fromhex(value)


def byte_array(value, size):
    require(type(value) is list and len(value) == size
            and all(type(byte) is int and 0 <= byte <= 255 for byte in value))
    return bytes(value)


def holder_id(public_key):
    """Validate canonical compressed P-256 point, then domain-hash its ID."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    raw = hex_value(public_key, 33)
    point = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    require(point.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint) == raw)
    return hashlib.sha256(HOLDER_DOMAIN + raw).hexdigest()


def challenge(core):
    require(type(core) is dict and set(core) == {'profile', 'policy_id', 'app_id', 'holder_public_key',
            'holder_key', 'purpose', 'seed', 'issued_at', 'expires_at'})
    require(core['profile'] == TICKET and core['purpose'] == PURPOSE)
    for key in ('policy_id', 'app_id', 'holder_key', 'purpose', 'seed'):
        hex_value(core[key], nonzero=True)
    require(holder_id(core['holder_public_key']) == core['holder_key'])
    require(type(core['issued_at']) is int and type(core['expires_at']) is int
            and 0 <= core['issued_at'] < 2**63 - LIFETIME
            and core['expires_at'] == core['issued_at'] + LIFETIME)
    return hashlib.sha256(CONTEXT_DOMAIN + canonical(core)).hexdigest()


def ticket_core(ticket):
    require(type(ticket) is dict and set(ticket) == {'profile', 'policy_id', 'app_id', 'holder_public_key',
            'holder_key', 'purpose', 'seed', 'issued_at', 'expires_at', 'challenge'})
    core = {key: value for key, value in ticket.items() if key != 'challenge'}
    require(ticket['challenge'] == challenge(core))
    return core


def validate_public(public, ticket):
    """Validate only public schemas/context, never an account or follower fact."""
    ticket_core(ticket)
    require(type(public) is dict and set(public) == {'json', 'application'})
    app = public['application']
    require(type(app) is dict and set(app) == {'version', 'program_id', 'policy_id', 'app_id',
            'request_id', 'expires_at', 'threshold', 'result', 'commitment'})
    require(type(app['version']) is int and app['version'] == 1 and app['program_id'] == PROGRAM_ID
            and app['policy_id'] == INNER_POLICY_ID and app['app_id'] == ticket['app_id']
            and app['request_id'] == ticket['challenge'] and app['expires_at'] == str(ticket['expires_at'])
            and type(app['threshold']) is int and app['threshold'] == 10000
            and type(app['result']) is int and app['result'] in (0, 1))
    commitment = hex_value(app['commitment'])
    obj = public['json']
    require(type(obj) is dict and set(obj) == {'http', 'account_commitment'})
    byte_array(obj['account_commitment'], 32)
    http = obj['http']
    require(type(http) is dict and set(http) == {'request', 'received_hash', 'received_length', 'body_hash', 'body_length'})
    for key in ('received_hash', 'body_hash'):
        byte_array(http[key], 32)
    for key in ('received_length', 'body_length'):
        require(type(http[key]) is int and 1 <= http[key] <= 8192)
    request = http['request']
    require(type(request) is dict and set(request) == {'application', 'holder_key', 'purpose', 'sent_hash', 'sent_length'})
    require(byte_array(request['holder_key'], 32).hex() == ticket['holder_key']
            and byte_array(request['purpose'], 32).hex() == ticket['purpose'])
    byte_array(request['sent_hash'], 32)
    require(type(request['sent_length']) is int and 1 <= request['sent_length'] <= 4096)
    opening = request['application']
    require(type(opening) is dict and set(opening) == {'app_id', 'request_id', 'expires_at', 'commitment'})
    require(byte_array(opening['app_id'], 32).hex() == ticket['app_id']
            and byte_array(opening['request_id'], 32).hex() == ticket['challenge']
            and type(opening['expires_at']) is int and opening['expires_at'] == ticket['expires_at']
            and byte_array(opening['commitment'], 32) == commitment)
    require(len(canonical(public)) <= 16384)
    return public
