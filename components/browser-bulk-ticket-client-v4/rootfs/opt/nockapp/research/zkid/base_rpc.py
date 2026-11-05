"""Bounded TLS JSON-RPC for an explicitly configured Base Sepolia provider.

The provider is a trust dependency, not a light client. No ambient proxy,
redirect, unlocked-account RPC, retries, credential discovery or payload logs.
"""
import json
import http.client
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from policy import require, strict_json

CHAIN_ID=84532
METHODS=frozenset({'eth_chainId','eth_getBlockByNumber','eth_getBlockByHash','eth_blockNumber',
    'eth_getLogs','eth_getTransactionReceipt','eth_getTransactionByHash','eth_getTransactionCount',
    'eth_getBalance','eth_getCode','eth_call','eth_estimateGas','eth_gasPrice',
    'eth_maxPriorityFeePerGas','eth_sendRawTransaction'})


class RPCError(ValueError):
    def __init__(self,code):
        self.code=code
        super().__init__('base-rpc-rejected')  # Provider text can contain secrets.


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None


class RelayHTTPS(urllib.request.HTTPSHandler):
    """TLS stays in the enclave; the fixed parent relay sees opaque bytes."""
    def __init__(self,host,context,dial):
        super().__init__(context=context)
        self.host,self.context,self.dial=host,context,dial

    def https_open(self,request):
        parent=self
        class Connection(http.client.HTTPSConnection):
            def connect(self):
                require(self._tunnel_host is None,'base-rpc-proxy')
                raw=parent.dial()
                try:
                    raw.settimeout(self.timeout)
                    self.sock=parent.context.wrap_socket(raw,server_hostname=parent.host)
                except Exception:raw.close();raise
        def create(host,**options):
            require(host in (self.host,self.host+':443'),'base-rpc-relay-host')
            return Connection(host,context=self.context,**options)
        return self.do_open(create,request)


class BaseRPC:
    def __init__(self,url,*,rate=8,burst=16,timeout=15,dial=None,context=None):
        parsed=urllib.parse.urlsplit(url)
        require(parsed.scheme=='https' and parsed.hostname is not None and parsed.username is None
            and parsed.password is None and not parsed.fragment and not parsed.query
            and parsed.port in (None,443),'base-rpc-endpoint')
        require(type(rate) is int and 0<rate<=100 and type(burst) is int and 0<burst<=100
            and type(timeout) is int and 0<timeout<=30,'base-rpc-budget')
        context=context or ssl.create_default_context()
        require(context.check_hostname and context.verify_mode==ssl.CERT_REQUIRED,'base-rpc-tls-context')
        handler=RelayHTTPS(parsed.hostname,context,dial) if dial is not None else urllib.request.HTTPSHandler(context=context)
        self._url=url;self._opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),handler)
        self._rate=rate;self._burst=burst;self._tokens=float(burst);self._last=time.monotonic()
        self._lock=threading.Lock();self._id=0;self._timeout=timeout
        self._counts={};self._errors=0;self._bytes=0

    def call(self,method,*params):
        require(method in METHODS,'base-rpc-method')
        with self._lock:
            now=time.monotonic();require(now>=self._last,'base-rpc-clock')
            self._tokens=min(self._burst,self._tokens+(now-self._last)*self._rate);self._last=now
            require(self._tokens>=1,'base-rpc-rate-limit');self._tokens-=1;self._id+=1;request_id=self._id
            self._counts[method]=self._counts.get(method,0)+1
        data=json.dumps({'jsonrpc':'2.0','id':request_id,'method':method,'params':params},
            separators=(',',':'),allow_nan=False).encode()
        require(len(data)<=262144,'base-rpc-request-size')
        request=urllib.request.Request(self._url,data,{'Content-Type':'application/json','Accept':'application/json',
            'User-Agent':'NockApp/0.5 (experimental Ubuntu beta)'})
        try:
            with self._opener.open(request,timeout=self._timeout) as response:
                require(response.status==200,'base-rpc-http')
                body=response.read(1048577)
            value=strict_json(body,max_bytes=1048576)
            require(value.get('jsonrpc')=='2.0' and type(value.get('id')) is int
                and value['id']==request_id and set(value) in ({'jsonrpc','id','result'},{'jsonrpc','id','error'}),
                'base-rpc-response')
            with self._lock:self._bytes+=len(body)
            if 'error' in value:
                error=value['error'];require(type(error) is dict and type(error.get('code')) is int,'base-rpc-response')
                raise RPCError(error['code'])
            return value['result']
        except RPCError:
            with self._lock:self._errors+=1
            raise
        except Exception:
            with self._lock:self._errors+=1
            raise ValueError('base-rpc-unavailable') from None

    def read_many(self,calls):
        """Bounded independent public reads, correlated by ID, never retried.

        Batching is not an atomic chain snapshot. Callers must explicitly pin
        block tags and retain their separate final canonical-anchor check.
        """
        allowed={'eth_chainId','eth_getBlockByNumber','eth_getTransactionReceipt','eth_getCode','eth_call'}
        require(type(calls) in (list,tuple) and 1<=len(calls)<=3,'base-rpc-batch-size')
        require(all(type(c) in (list,tuple) and len(c)==2 and type(c[0]) is str
            and c[0] in allowed and type(c[1]) in (list,tuple) for c in calls),'base-rpc-batch-method')
        # Admit serialization/size before charging the shared logical-call budget.
        require(len(json.dumps(calls,allow_nan=False).encode())<=240000,'base-rpc-request-size')
        with self._lock:
            now=time.monotonic();require(now>=self._last,'base-rpc-clock')
            self._tokens=min(self._burst,self._tokens+(now-self._last)*self._rate);self._last=now
            require(self._tokens>=len(calls),'base-rpc-rate-limit');self._tokens-=len(calls)
            requests=[]
            for method,params in calls:
                self._id+=1;requests.append({'jsonrpc':'2.0','id':self._id,'method':method,'params':params})
                self._counts[method]=self._counts.get(method,0)+1
        data=json.dumps(requests,separators=(',',':'),allow_nan=False).encode()
        require(len(data)<=262144,'base-rpc-request-size')
        request=urllib.request.Request(self._url,data,{'Content-Type':'application/json','Accept':'application/json',
            'User-Agent':'NockApp/0.5 (experimental Ubuntu beta)'})
        try:
            limit=1048566  # Reserve ten bytes for the strict parser's object wrapper.
            with self._opener.open(request,timeout=self._timeout) as response:
                require(response.status==200,'base-rpc-http');body=response.read(limit+1)
            values=strict_json(b'{"batch":'+body+b'}',max_bytes=1048576)['batch']
            require(type(values) is list and len(values)==len(calls),'base-rpc-batch-response')
            ids={r['id'] for r in requests};seen={}
            for v in values:
                require(type(v) is dict and v.get('jsonrpc')=='2.0' and type(v.get('id')) is int
                    and v['id'] in ids and v['id'] not in seen
                    and set(v) in ({'jsonrpc','id','result'},{'jsonrpc','id','error'})
                    and len(json.dumps(v,separators=(',',':'),allow_nan=False).encode())<=1048576,
                    'base-rpc-batch-response')
                if 'error' in v:
                    require(type(v['error']) is dict and type(v['error'].get('code')) is int,'base-rpc-response')
                seen[v['id']]=v
            require(set(seen)==ids,'base-rpc-batch-response')
            with self._lock:self._bytes+=len(body)
            for r in requests:
                if 'error' in seen[r['id']]:raise RPCError(seen[r['id']]['error']['code'])
            return [seen[r['id']]['result'] for r in requests]
        except RPCError:
            with self._lock:self._errors+=1
            raise
        except Exception:
            with self._lock:self._errors+=1
            raise ValueError('base-rpc-unavailable') from None

    def check_identity(self,contracts):
        """Pin expected chain and each configured runtime-code SHA256 digest."""
        import hashlib
        require(self.call('eth_chainId')==hex(CHAIN_ID),'base-chain-identity')
        require(type(contracts) is dict,'base-contract-config')
        for address,expected in contracts.items():
            require(type(address) is str and len(address)==42 and address.startswith('0x')
                and type(expected) is str and len(expected)==64,'base-contract-config')
            try:code=bytes.fromhex(self.call('eth_getCode',address,'finalized')[2:])
            except Exception:raise ValueError('base-contract-unavailable') from None
            require(bool(code) and hashlib.sha256(code).hexdigest()==expected,'base-contract-identity')
        return True

    def keccak(self,data):
        from base_protocol import keccak
        return keccak(data)

    def metrics(self):
        with self._lock:return {'calls':dict(self._counts),'errors':self._errors,'response_bytes':self._bytes}
