"""Holder cryptography only. Signatures prove possession, never source facts.

Freshness/replay and supported credential facts belong to the independent
verifier. Domain-separated messages prevent issuance/action substitution.
"""
import re
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from x_policy import canonical, require, hex_value, holder_id, ticket_core

ISSUANCE_POP = 'nockapp-x-holder-issuance-pop-v1'
ACTION_POP = 'nockapp-x-holder-action-pop-v1'
ISSUANCE_DOMAIN = b'NOCKAPP/HOLDER/X-ISSUANCE-POP/v1\0'
ACTION_DOMAIN = b'NOCKAPP/HOLDER/X-ACTION-POP/v1\0'
FACTS = {'account-controlled', 'followers-over-10000'}


def public_hex(key):
    require(isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256R1))
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint).hex()


def issuance_message(ticket):
    ticket_core(ticket)
    return ISSUANCE_DOMAIN + canonical(ticket)


def action_message(action):
    require(type(action) is dict and set(action) == {'profile', 'credential_id', 'purpose', 'challenge',
            'expires_at', 'audience', 'fact'} and action['profile'] == ACTION_POP
            and type(action['fact']) is str and action['fact'] in FACTS)
    for key in ('credential_id', 'purpose', 'challenge', 'audience'):
        hex_value(action[key], nonzero=True)
    require(type(action['expires_at']) is int and 0 < action['expires_at'] < 2**63)
    return ACTION_DOMAIN + canonical(action)


def sign(key, message, profile):
    public_hex(key)
    signature = key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(signature)
    order = ec.SECP256R1().group_order
    signature = utils.encode_dss_signature(r, min(s, order - s))
    return {'profile': profile, 'signature': signature.hex()}


def verify(public_key, message, proof, profile):
    try:
        holder_id(public_key)
        require(type(proof) is dict and set(proof) == {'profile', 'signature'} and proof['profile'] == profile)
        encoded = proof['signature']
        require(type(encoded) is str and 16 <= len(encoded) <= 144 and len(encoded) % 2 == 0
                and re.fullmatch(r'[0-9a-f]+', encoded) is not None)
        signature = bytes.fromhex(encoded)
        r, s = utils.decode_dss_signature(signature)
        order = ec.SECP256R1().group_order
        require(0 < r < order and 0 < s <= order // 2 and utils.encode_dss_signature(r, s) == signature)
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(public_key))
        key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def sign_issuance(key, ticket):
    message = issuance_message(ticket)
    require(public_hex(key) == ticket['holder_public_key'])
    return sign(key, message, ISSUANCE_POP)


def verify_issuance(ticket, proof):
    try:
        return verify(ticket['holder_public_key'], issuance_message(ticket), proof, ISSUANCE_POP)
    except Exception:
        return False


def sign_action(key, action):
    return sign(key, action_message(action), ACTION_POP)


def verify_action(public_key, action, proof):
    try:
        return verify(public_key, action_message(action), proof, ACTION_POP)
    except Exception:
        return False
