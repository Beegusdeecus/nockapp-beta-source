"""Explicit same-pack recovery through an ALREADY delegated wallet.

Never upgrades the account, replaces blind inputs, arms a new pack or broadcasts.
Every inner buy targets the original immutable paid-once contract. Revert-on-
failure execution makes competing identical batches mutually exclusive; a losing
transaction may still spend gas. Owner review/signature is always required.
"""
import copy
from policy import require,digest
from base_protocol import keccak
from ticket_payment_v1 import FinalizedTicketPayment,_quantity
from ticket_payment_recovery_v2 import require_unpaid,check_anchor
from ticket_wallet_v1 import payment_anchor

IMPLEMENTATION='0x63c0c19a282a1b52b07dd5a65b58948a07dae32b'
IMPLEMENTATION_HASH='0x83805f9ac7395294043b10c3b7c1839b7e4582a3e693028c36df84978b09d4e2'
DELEGATION='0xef0100'+IMPLEMENTATION[2:]
MODE='01'+'00'*31  # Batch + revert-on-failure; never EXECTYPE_TRY.
PROFILE='nockapp-same-purchase-review-v1'
DISPATCH='nockapp-same-purchase-dispatch-v1'
MAX_GAS=2000000
MAX_EXECUTION_FEE=10**15
WINDOW=180

def word(n):return format(n,'064x')

def calldata(b,offer):
    require(b['profile']=='nockapp-ticket-bulk-purchase-v1'and len(b['items'])==25,'same-purchase-format')
    price=int(offer.terms['pack_price_wei']);target=offer.manifest['purchase_contract'][2:].rjust(64,'0')
    tuples=[target+word(price)+word(96)+word(36)+'9c9a1061'+p['pack_hash'][2:]+'00'*28 for p in b['items']]
    # abi.encode(Execution[]): offsets are relative to the array head after length.
    execution=word(32)+word(25)+''.join(word(25*32+i*192)for i in range(25))+''.join(tuples)
    return '0xe9ae5c53'+MODE+word(64)+word(len(execution)//2)+execution

def validate(q,b,offer):
    fields={'profile','parameters','batch_id','payer','transaction','implementation','implementation_keccak',
        'attempt_number','price_wei','execution_fee_limit_wei','execution_fee_wei','checked_through','expires_at','quote_sha256'}
    require(type(q)is dict and set(q)==fields and q['profile']==PROFILE,'same-purchase-quote')
    require(q['parameters']==offer.hash and q['batch_id']==b['batch_id']and q['payer']==b['payer']
        and q['implementation']==IMPLEMENTATION and q['implementation_keccak']==IMPLEMENTATION_HASH,'same-purchase-context')
    require(type(q['attempt_number'])is int and 1<=q['attempt_number']<=8,'same-purchase-attempt-limit')
    price=25*int(offer.terms['pack_price_wei']);t=q['transaction']
    require(type(t)is dict and set(t)=={'chainId','from','to','value','data','nonce','gas','gasPrice'}
        and t['chainId']=='0x14a34'and t['from']==t['to']==b['payer']
        and t['value']==hex(price)and t['data']==calldata(b,offer),'same-purchase-transaction')
    require(_quantity(t['nonce'])<2**64 and 21000<=_quantity(t['gas'])<=MAX_GAS
        and 0<_quantity(t['gasPrice'])<2**128,'same-purchase-fee')
    for key in ('price_wei','execution_fee_limit_wei','execution_fee_wei'):
        require(type(q[key])is str and q[key].isdigit()and str(int(q[key]))==q[key],'same-purchase-fee')
    require(q['price_wei']==str(price)and int(q['execution_fee_wei'])==_quantity(t['gas'])*_quantity(t['gasPrice'])
        and 0<int(q['execution_fee_wei'])<=int(q['execution_fee_limit_wei'])<=MAX_EXECUTION_FEE,'same-purchase-fee')
    payment_anchor(q['checked_through']);require(_quantity(q['checked_through']['number'])>=_quantity(b['anchor']['number']),'same-purchase-anchor')
    require(type(q['expires_at'])is int and 0<q['expires_at']<2**53,'same-purchase-clock')
    require(q['quote_sha256']==digest({k:v for k,v in q.items()if k!='quote_sha256'}),'same-purchase-digest')
    return q

def validate_fence(value,b,offer):
    require(type(value)is dict and set(value)=={'profile','attempts','quote'}
        and value['profile']=='nockapp-same-purchase-fence-v1','same-purchase-fence')
    require(b['phase']!='prepared','same-purchase-fence')
    rows=value['attempts'];require(type(rows)is list and 1<=len(rows)<=8,'same-purchase-attempt-limit')
    seen=set();reserved=0;previous=-1
    for row in rows:
        require(type(row)is dict and set(row)=={'quote_sha256','nonce','execution_fee_wei'}
            and type(row['quote_sha256'])is str and len(row['quote_sha256'])==64
            and all(c in '0123456789abcdef'for c in row['quote_sha256'])
            and row['quote_sha256']not in seen,'same-purchase-fence')
        seen.add(row['quote_sha256']);nonce=_quantity(row['nonce'])
        require(previous<=nonce<2**64 and type(row['execution_fee_wei'])is str
            and row['execution_fee_wei'].isdigit()and str(int(row['execution_fee_wei']))==row['execution_fee_wei']
            and 0<int(row['execution_fee_wei'])<=MAX_EXECUTION_FEE,'same-purchase-fence')
        previous=nonce;reserved+=int(row['execution_fee_wei'])
    require(reserved<=MAX_EXECUTION_FEE,'same-purchase-execution-budget')
    q=validate(value['quote'],b,offer);require(q['attempt_number']==len(rows),'same-purchase-fence')
    require(rows[-1]=={'quote_sha256':q['quote_sha256'],'nonce':q['transaction']['nonce'],
        'execution_fee_wei':q['execution_fee_wei']},'same-purchase-fence')
    return value

def preflight(rpc,b,offer):
    require(b['profile']=='nockapp-ticket-bulk-purchase-v1'and b['phase']=='armed'
        and b['transaction_hash']is None and b['imported']==0,'same-purchase-already-paid-or-settled')
    final=FinalizedTicketPayment(rpc,offer).preflight();latest=rpc.call('eth_getBlockByNumber','latest',False)
    require(type(latest)is dict and _quantity(final['number'])<=_quantity(latest['number'])
        and _quantity(latest['timestamp'])<offer.terms['purchase_before'],'same-purchase-expired')
    for block in (final,latest):
        tag=block['number']
        require(rpc.call('eth_getCode',b['payer'],tag)==DELEGATION,'same-purchase-wallet-not-approved')
        code=rpc.call('eth_getCode',IMPLEMENTATION,tag)
        require(type(code)is str and code.startswith('0x')and len(code)<=32770
            and keccak(bytes.fromhex(code[2:]))==IMPLEMENTATION_HASH,'same-purchase-wallet-code')
        for item in b['items']:require_unpaid(rpc,offer,item['pack_hash'],tag)
    check_anchor(rpc,b['anchor']);check_anchor(rpc,{k:final[k]for k in ('number','hash')})
    check_anchor(rpc,{k:latest[k]for k in ('number','hash')})
    return {k:final[k]for k in ('number','hash')}

def review(bulk,fee_limit,now):
    require(type(fee_limit)is str and fee_limit.isdigit()and str(int(fee_limit))==fee_limit
        and 0<int(fee_limit)<=MAX_EXECUTION_FEE and type(now)is int,'same-purchase-fee')
    with bulk.tickets.wallet.controller_lock():
        b=bulk._read();require(b is not None,'same-purchase-missing')
        require(len(b.get('resume_payment',{}).get('attempts',[]))<8,'same-purchase-attempt-limit')
        anchor=preflight(bulk.rpc,b,bulk.tickets.offer)
        tx={'chainId':'0x14a34','from':b['payer'],'to':b['payer'],
            'value':hex(25*int(bulk.tickets.offer.terms['pack_price_wei'])),'data':calldata(b,bulk.tickets.offer)}
        require(bulk.rpc.call('eth_call',tx,'latest')=='0x','same-purchase-simulation')
        gas=(_quantity(bulk.rpc.call('eth_estimateGas',tx))*125+99)//100
        price=_quantity(bulk.rpc.call('eth_gasPrice'));nonce=_quantity(bulk.rpc.call('eth_getTransactionCount',b['payer'],'pending'))
        require(21000<=gas<=MAX_GAS and price>0 and gas*price<=int(fee_limit),'same-purchase-fee')
        require(_quantity(bulk.rpc.call('eth_getBalance',b['payer'],'latest'))>=int(tx['value'],16)+gas*price,'same-purchase-balance')
        tx.update(nonce=hex(nonce),gas=hex(gas),gasPrice=hex(price))
        q={'profile':PROFILE,'parameters':bulk.tickets.offer.hash,'batch_id':b['batch_id'],'payer':b['payer'],
            'transaction':tx,'implementation':IMPLEMENTATION,'implementation_keccak':IMPLEMENTATION_HASH,
            'attempt_number':len(b.get('resume_payment',{}).get('attempts',[]))+1,'price_wei':str(int(tx['value'],16)),'execution_fee_limit_wei':fee_limit,'execution_fee_wei':str(gas*price),
            'checked_through':anchor,'expires_at':now+WINDOW}
        q['quote_sha256']=digest(q);validate(q,b,bulk.tickets.offer)
        previous=b.get('resume_payment',{}).get('attempts',[])
        validate_fence({'profile':'nockapp-same-purchase-fence-v1','attempts':copy.deepcopy(previous)+[
            {'quote_sha256':q['quote_sha256'],'nonce':tx['nonce'],'execution_fee_wei':q['execution_fee_wei']}],'quote':q},b,bulk.tickets.offer)
        return q

def arm(bulk,q,approve,now):
    require(approve is True and type(now)is int,'consent-required')
    with bulk.tickets.wallet.controller_lock():
        b=bulk._read();require(b is not None,'same-purchase-missing')
        validate(q,b,bulk.tickets.offer)
        require(now<q['expires_at']<=now+WINDOW,'same-purchase-review-expired')
        preflight(bulk.rpc,b,bulk.tickets.offer);check_anchor(bulk.rpc,q['checked_through']);t=q['transaction']
        require(bulk.rpc.call('eth_getTransactionCount',b['payer'],'pending')==t['nonce'],'same-purchase-nonce-changed')
        require(_quantity(bulk.rpc.call('eth_gasPrice'))<=_quantity(t['gasPrice']),'same-purchase-fee-changed')
        require(_quantity(bulk.rpc.call('eth_getBalance',b['payer'],'latest'))>=int(t['value'],16)+int(q['execution_fee_wei']),'same-purchase-balance')
        require(bulk.rpc.call('eth_call',t,'latest')=='0x'
            and _quantity(bulk.rpc.call('eth_estimateGas',t))<=_quantity(t['gas']),'same-purchase-simulation')
        # Persist before issuing one dispatch authorization. The original batch,
        # anchor, pack/blind inputs, payer and import cursor are unchanged.
        previous=b.get('resume_payment',{}).get('attempts',[])
        require(q['attempt_number']==len(previous)+1 and len(previous)<8 and all(v['quote_sha256']!=q['quote_sha256']for v in previous),'same-purchase-attempt-limit')
        b['resume_payment']={'profile':'nockapp-same-purchase-fence-v1',
            'attempts':copy.deepcopy(previous)+[{'quote_sha256':q['quote_sha256'],'nonce':t['nonce'],'execution_fee_wei':q['execution_fee_wei']}],
            'quote':copy.deepcopy(q)}
        validate_fence(b['resume_payment'],b,bulk.tickets.offer);bulk._write(b)
        return {'profile':DISPATCH,'quote':copy.deepcopy(q),'dispatch_authorized':True}
