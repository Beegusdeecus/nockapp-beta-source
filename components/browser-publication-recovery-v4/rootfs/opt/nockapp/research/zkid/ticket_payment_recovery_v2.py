"""Bounded finalized sender/nonce discovery, never send/retry authorization.

Uses configured archival RPC state, not a consensus light client. Binary search
locates the first block whose account nonce passed the saved nonce. At most53
midpoints, one block (<=2048 transactions/1MiB), and one receipt are examined.
Missing/pruned/inconsistent data fail closed without changing the wallet.
"""
import copy
import time
from types import SimpleNamespace
from base_evm import encode
from policy import require,canonical,Rejected
from ticket_offer_v1 import hex_value
from ticket_payment_v1 import _quantity,FinalizedTicketPayment
from ticket_wallet_v1 import PAYMENT_INTENT_V2,CLOSED_PAYMENT,payment_anchor,payment_transaction,closed_payment

MAX_TRANSACTIONS=2048


def budgeted_rpc(rpc,*,clock=None,pause=None,max_calls=64):
    clock=clock or time.monotonic;pause=pause or time.sleep
    started=clock();previous=None;calls=0

    def call(method,*args):
        # Stay below the installed RPC's eight requests/second allowance;
        # never retry a missing, timed out or rate-limited response.
        nonlocal previous,calls
        now=clock()
        require(now>=started and (previous is None or now>=previous),'ticket-payment-search-clock')
        if previous is not None and now-previous<0.13:pause(0.13-(now-previous))
        before=clock()
        require(before>=now and before-started<=25 and calls<max_calls,'ticket-payment-search-budget')
        previous=before;calls+=1
        result=rpc.call(method,*args)
        after=clock()
        require(after>=before and after-started<=25,'ticket-payment-search-budget')
        return result

    return SimpleNamespace(call=call)


def check_anchor(rpc,anchor):
    payment_anchor(anchor)
    block=rpc.call('eth_getBlockByNumber',anchor['number'],False)
    require(type(block) is dict and block.get('number')==anchor['number']
        and block.get('hash')==anchor['hash'],'ticket-payment-finality-changed')


def check_closed_payments(rpc,proofs,final):
    """Recheck terminal fences before a new attempt; no trusted cached verdict."""
    for proof in proofs:
        closed_payment(proof)
        require(int(proof['checked_through']['number'],16)<=int(final['number'],16),
            'ticket-payment-finality-changed')
        check_anchor(rpc,proof['transaction_block']);check_anchor(rpc,proof['checked_through'])


def require_unpaid(rpc,offer,pack_hash,tag):
    hex_value(pack_hash,32)
    require(rpc.call('eth_call',{'to':offer.manifest['purchase_contract'],
        'data':encode('paid(bytes32)',pack_hash)},tag)=='0x'+'0'*64,'ticket-pack-already-paid')


def find_payment(rpc,view,*,clock=None,pause=None,_budgeted=False):
    call=(rpc if _budgeted else budgeted_rpc(rpc,clock=clock,pause=pause)).call

    intent=view['payment_intent']
    require(type(intent) is dict and set(intent)=={'profile','payer','nonce','anchor'}
        and intent['profile']==PAYMENT_INTENT_V2,'ticket-payment-search-anchor-required')
    start=payment_anchor(intent['anchor']);payer=hex_value(intent['payer'],20);nonce=intent['nonce']
    require(type(nonce) is int and 0<=nonce<2**64,'ticket-payment-nonce')
    require(call('eth_chainId')=='0x14a34','ticket-payment-chain')
    final=call('eth_getBlockByNumber','finalized',False)
    require(type(final) is dict,'ticket-payment-finality')
    end=payment_anchor({'number':final.get('number'),'hash':final.get('hash')})
    low,high=_quantity(start['number']),_quantity(end['number'])
    require(low<=high,'ticket-payment-search-range')

    def check(anchor):
        check_anchor(SimpleNamespace(call=call),anchor)

    def count(height):
        value=_quantity(call('eth_getTransactionCount',payer,hex(height)))
        require(value<2**64,'ticket-payment-nonce')
        return value

    check(start)
    left,right=count(low),count(high)
    require(left<=nonce and left<=right,'ticket-payment-search-nonce')

    def finish(state,**extra):
        check(start);check(end)
        return {'state':state,'checked_through':copy.deepcopy(end),**extra}

    if right<=nonce:return finish('not-finalized')
    for _ in range(53):
        if low+1>=high:break
        mid=(low+high)//2;value=count(mid)
        require(left<=value<=right,'ticket-payment-search-nonce')
        if value<=nonce:low,left=mid,value
        else:high,right=mid,value
    require(low+1==high,'ticket-payment-search-budget')
    block=call('eth_getBlockByNumber',hex(high),True)
    require(type(block) is dict and block.get('number')==hex(high),'ticket-payment-search-block')
    block_hash=hex_value(block.get('hash'),32);transactions=block.get('transactions')
    require(type(transactions) is list and len(transactions)<=MAX_TRANSACTIONS
        and all(type(tx) is dict for tx in transactions),'ticket-payment-search-block-budget')
    require(len(canonical(block))<=1048576,'ticket-payment-search-block-budget')
    matches=[(i,tx) for i,tx in enumerate(transactions)
        if tx.get('from')==payer and tx.get('nonce')==hex(nonce)]
    require(len(matches)<=1,'ticket-payment-search-duplicate')
    if not matches:return finish('nonce-consumed-unresolved')
    position,tx=matches[0];transaction_hash=hex_value(tx.get('hash'),32)
    require(tx.get('blockNumber')==hex(high) and tx.get('blockHash')==block_hash
        and tx.get('transactionIndex')==hex(position),'ticket-payment-search-inclusion')
    receipt=call('eth_getTransactionReceipt',transaction_hash)
    require(type(receipt) is dict and receipt.get('transactionHash')==transaction_hash
        and receipt.get('blockNumber')==hex(high) and receipt.get('blockHash')==block_hash
        and receipt.get('transactionIndex')==hex(position)
        and receipt.get('status') in ('0x0','0x1'),'ticket-payment-search-receipt')
    exact=call('eth_getBlockByNumber',hex(high),False)
    require(type(exact) is dict and exact.get('number')==hex(high) and exact.get('hash')==block_hash
        and type(exact.get('transactions')) is list and len(exact['transactions'])==len(transactions)
        and exact['transactions'][position]==transaction_hash,'ticket-payment-finality-changed')
    try:payment_transaction(view,tx)
    except Rejected:
        return finish('nonce-consumed-by-other-transaction',transaction_hash=transaction_hash,
            transaction_block={'number':hex(high),'hash':block_hash},receipt_status=receipt['status'])
    return finish('transaction-found',transaction=copy.deepcopy(tx),receipt_status=receipt['status'],
        transaction_block={'number':hex(high),'hash':block_hash})


def failed_payment_proof(rpc,offer,view,previous=(),*,clock=None,pause=None):
    """Read-only terminal proof; the caller still needs explicit close consent.

    Pending, missing, unresolved or successful exact payments cannot close. A
    A consumed EOA nonce does not fence a delayed delegated/relayed call. The
    immutable purchase deadline must also have passed at a finalized anchor.
    The pinned pack must be unpaid both at the checked final anchor and latest.
    """
    rpc=budgeted_rpc(rpc,clock=clock,pause=pause,max_calls=96)
    initial=FinalizedTicketPayment(rpc,offer).preflight()
    require(_quantity(initial['timestamp'])>=offer.terms['purchase_before'],
        'ticket-payment-relay-window-open')
    check_closed_payments(rpc,previous,initial)
    found=find_payment(rpc,view,_budgeted=True)
    require(found['state']=='nonce-consumed-by-other-transaction' or
        found['state']=='transaction-found' and found['receipt_status']=='0x0','ticket-payment-not-terminal-unpaid')
    require_unpaid(rpc,offer,view['pack_hash'],found['checked_through']['number'])
    require_unpaid(rpc,offer,view['pack_hash'],'latest')
    check_anchor(rpc,found['transaction_block']);check_anchor(rpc,found['checked_through'])
    check_anchor(rpc,{'number':initial['number'],'hash':initial['hash']})
    proof={'profile':CLOSED_PAYMENT,'parameters':offer.hash,'pack_hash':view['pack_hash'],
        'intent':copy.deepcopy(view['payment_intent']),
        'transaction_hash':found.get('transaction_hash') or found['transaction']['hash'],
        'transaction_block':found['transaction_block'],'checked_through':found['checked_through'],
        'outcome':'failed' if found['state']=='transaction-found' else 'other-transaction'}
    return closed_payment(proof)
