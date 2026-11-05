"""Loopback-only local EVM harness. No remote transaction or private-key CLI.

Pinned tooling lives under ignored local/base-tools. This is a laboratory node,
not a Base node; execution gas measurements omit Base L1-data/operator fees.
"""
from contextlib import contextmanager
import json
from pathlib import Path
import socket
import subprocess
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parent
TOOLS = ROOT/'local/base-tools'


class RPC:
    def __init__(self, port):
        assert type(port) is int and 0 < port < 65536
        self.url = f'http://127.0.0.1:{port}'
        self.transaction_lock = threading.Lock()

    def call(self, method, *params):
        request = urllib.request.Request(self.url, json.dumps({
            'jsonrpc':'2.0', 'id':1, 'method':method, 'params':params}).encode(),
            {'Content-Type':'application/json'})
        # Never use process proxy configuration, even for loopback.
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=20) as r:
            value = json.load(r)
        if 'error' in value:
            raise ValueError(value['error'])
        return value['result']

    def keccak(self, data):
        return self.call('web3_sha3', '0x'+data.hex())

    def tx(self, sender, data, to=None, gas=15000000):
        # One local node-managed nonce queue. Production issuer transactions
        # need the same single-writer nonce discipline and lost-reply recovery.
        with self.transaction_lock:
            return self._tx(sender,data,to,gas)

    def _tx(self, sender, data, to, gas):
        value = {'from':sender, 'data':data, 'gas':hex(gas)}
        if to is not None:
            value['to'] = to
        tx = self.call('eth_sendTransaction', value)
        deadline = time.monotonic()+20
        while time.monotonic() < deadline:
            receipt = self.call('eth_getTransactionReceipt', tx)
            if receipt:
                return receipt
            time.sleep(.01)
        raise TimeoutError('local-transaction-not-mined')


@contextmanager
def local_chain(state=None, timestamp=1793011200,*,chain_id=31337):
    if type(chain_id) is not int or chain_id not in (31337,84532):raise ValueError('local-chain-id')
    with socket.socket() as s:
        s.bind(('127.0.0.1',0))
        port = s.getsockname()[1]
    args = [str(TOOLS/'anvil'), '--host','127.0.0.1','--port',str(port),
            '--hardfork','prague','--chain-id',str(chain_id),'--timestamp',str(timestamp),'--quiet','--no-cors']
    if state is not None:
        args += ['--state',str(state),'--preserve-historical-states']
    p = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    rpc = RPC(port)
    try:
        deadline = time.monotonic()+10
        while True:
            if p.poll() is not None:
                raise RuntimeError('local-node-exited')
            try:
                assert int(rpc.call('eth_chainId'),16) == chain_id
                break
            except (OSError, ValueError):
                if time.monotonic() >= deadline:
                    raise TimeoutError('local-node-start')
                time.sleep(.02)
        yield rpc
    finally:
        p.terminate()
        try:
            p.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill(); p.communicate()


def compile_contracts():
    sources = {str(p.relative_to(ROOT/'base')):{'content':p.read_text()}
               for p in sorted((ROOT/'base/contracts').glob('*.sol'))}
    request = {'language':'Solidity','sources':sources,'settings':{
        'optimizer':{'enabled':True,'runs':200}, 'evmVersion':'prague',
        'outputSelection':{'*':{'*':['abi','evm.bytecode.object','evm.deployedBytecode.object']}}}}
    done = subprocess.run([str(TOOLS/'solc-0.8.30'),'--standard-json'],
                          input=json.dumps(request).encode(),capture_output=True,check=True)
    result = json.loads(done.stdout)
    if any(e['severity']=='error' for e in result.get('errors',[])):
        raise ValueError(result['errors'])
    return result['contracts']


def encode(signature, *args):
    # Public ABI values only. Private keys/credentials never use this path.
    done = subprocess.run([str(TOOLS/'cast'),'calldata',signature,*map(str,args)],
                          capture_output=True,check=True,timeout=10)
    return done.stdout.decode().strip()
