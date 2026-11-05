"""Small bounded protocol and reproducible public identity helpers."""
import base64
import hashlib
import json
import socket
import struct
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / 'target/release/tlsnotary-vendor-core'
MAX_MESSAGE = 2_000_000
POLICY = {
    'id': 'tlsnotary-vendor-policy-v1',
    'tlsnotary_revision': '47aee45b53e06648c1b2ad3689b367b8c923fdec',
    'protocol': 'mpc-tls', 'source_tls': '1.2',
    'max_sent': 1024, 'max_received': 2048,
    'signature': 'secp256k1', 'commitment': 'sha256',
    'mpc_cpu_limit': 1, 'extensions': False, 'sessions_per_key': 1, 'session_deadline_seconds': 120,
}
# Separate, opt-in fixed policy. Never negotiate these limits with the claimant.
OPAQUE_POLICY = {**POLICY, 'id': 'tlsnotary-vendor-opaque-policy-v2',
                 'max_sent': 4096, 'max_received': 8192,
                 'max_received_online': 32, 'defer_decryption_from_start': True,
                 'max_concurrent_sessions': 2, 'notary_address_space_bytes': 2147483648,
                 'disclosure': 'none', 'commitment_scope': 'both-complete-streams'}

def require(condition, message):
    if not condition:
        raise ValueError(message)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()

def digest(data):
    return hashlib.sha256(data).hexdigest()

def b64(data):
    return base64.b64encode(data).decode('ascii')

def unb64(value):
    require(isinstance(value, str) and len(value) <= MAX_MESSAGE, 'invalid base64 size')
    return base64.b64decode(value, validate=True)

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON field')
        result[key] = value
    return result

def loads(data):
    require(len(data) <= MAX_MESSAGE, 'message limit exceeded')
    return json.loads(data, object_pairs_hook=unique_object)

def read_json(path):
    with open(path, 'rb') as stream:
        return loads(stream.read(MAX_MESSAGE + 1))

def write_json(path, value):
    Path(path).write_bytes(canonical(value) + b'\n')

def read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise EOFError('truncated transport')
        data.extend(part)
    return bytes(data)

def send_json(sock, value):
    data = canonical(value)
    require(len(data) <= MAX_MESSAGE, 'message limit exceeded')
    sock.sendall(struct.pack('!I', len(data)) + data)

def receive_json(sock):
    size, = struct.unpack('!I', read_exact(sock, 4))
    require(size <= MAX_MESSAGE, 'message limit exceeded')
    return loads(read_exact(sock, size))

def tcp_address(address):
    host, port = address.rsplit(':', 1)
    return host, int(port)

def core_run(mode, config, cancel_event=None):
    with subprocess.Popen([str(CORE), mode], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        deadline=time.monotonic()+130
        data=canonical(config)
        try:
            while True:
                try:
                    output,error=process.communicate(input=data, timeout=0.2)
                    break
                except subprocess.TimeoutExpired:
                    data=None
                    require(cancel_event is None or not cancel_event.is_set(), 'attested channel aborted')
                    require(time.monotonic()<deadline, 'TLSNotary core deadline exceeded')
            require(process.returncode == 0, 'TLSNotary core rejected operation: ' + error.decode(errors='replace')[:1000])
            return loads(output)
        finally:
            if process.poll() is None:process.kill()
            process.communicate()

def code_identity(root_der):
    # Explicit files only: never scan environment files or arbitrary working trees.
    paths = [CORE, ROOT/'Cargo.lock', ROOT/'Cargo.toml', ROOT/'src/main.rs',
             ROOT/'requirements.lock']
    paths += sorted((ROOT/'vendor_service').glob('*.py'))
    manifest = {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in paths}
    manifest['source_root_der'] = digest(root_der)
    return digest(canonical(manifest))

def binding(public_key, channel_cert, identity, policy=POLICY):
    return {'domain': 'tlsnotary-vendor-attested-channel-v1',
            'notary_key': public_key, 'channel_certificate_sha256': digest(channel_cert),
            'policy_sha256': digest(canonical(policy)), 'code_identity': identity}
