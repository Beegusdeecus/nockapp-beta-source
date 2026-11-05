"""Explicit cumulative-cap migration for the existing managed signer journal.

Trusted deployment API only. A public plan/hash records the reviewed change;
it is not an authorization token. No browser route, signing, funding, journal
creation/reset, key export, contract change or per-transaction fee increase.
The original records and nonce range survive an authenticated, atomic CAS.
"""
from dataclasses import asdict
import copy
import hashlib

from cryptography.exceptions import InvalidTag
from base_fees import policy as fee_policy
from base_transactions import Limits, TransactionQueue
from policy import canonical, digest, hex_string, require

PROFILE = 'nockapp-base-cumulative-budget-upgrade-v1'


def contexts(chain, signer_address, contracts, limits, fees, code_hashes, previous, laboratory):
    require(type(limits) is Limits and type(previous) is dict
            and set(previous) == {'profile', 'previous_limits', 'previous_fee_policy',
                                  'old_context_sha256', 'new_context_sha256'}
            and previous['profile'] == PROFILE, 'budget-upgrade-plan')
    limits.validate()
    require(type(previous['previous_limits']) is dict
            and set(previous['previous_limits']) == set(asdict(limits)), 'budget-upgrade-limits')
    old_limits = Limits(**previous['previous_limits'])
    old_limits.validate()
    new_fees, old_fees = fee_policy(fees), fee_policy(previous['previous_fee_policy'])
    old, new = asdict(old_limits), asdict(limits)
    for field in ('max_gas', 'max_fee_per_gas', 'priority_fee'):
        require(old[field] == new[field], 'budget-upgrade-per-transaction-limit')
    cumulative = ('execution_budget', 'max_submissions')
    require(all(old[field] <= new[field] for field in cumulative), 'budget-upgrade-decrease')
    allowed = ('total_budget', 'funded_budget')
    require({k: v for k, v in old_fees.items() if k not in allowed}
            == {k: v for k, v in new_fees.items() if k not in allowed}, 'budget-upgrade-fee-policy')
    require(all(old_fees[field] <= new_fees[field] for field in allowed), 'budget-upgrade-decrease')
    require(old != new or old_fees != new_fees, 'budget-upgrade-no-change')
    require(chain == (31337 if laboratory else 84532), 'budget-upgrade-chain')
    require(type(contracts) is dict and contracts, 'budget-upgrade-contracts')
    normalized = {address.lower(): sorted(set(s.lower() for s in selectors))
                  for address, selectors in contracts.items()}
    common = {'profile': 'nockapp-base-transaction-journal-v3', 'chain': chain,
              'signer': signer_address.lower(), 'contracts': normalized, 'code_hashes': code_hashes}
    old_context = canonical({**common, 'limits': old, 'fee_policy': old_fees}).decode()
    new_context = canonical({**common, 'limits': new, 'fee_policy': new_fees}).decode()
    for key, text in (('old_context_sha256', old_context), ('new_context_sha256', new_context)):
        hex_string(previous[key], 64)
        require(hashlib.sha256(text.encode()).hexdigest() == previous[key], 'budget-upgrade-context-pin')
    return old_limits, old_fees, old_context, new_context


def resume(rpc, signer, path, contracts, limits, *, anchor, fees, code_hashes,
           upgrade, upgrade_sha256, laboratory=False):
    """Resume new context first; migrate only the exact authenticated old one.

    Call only after the new caps and measured deployment have been approved.
    Lost CAS replies never trigger an old-state rewrite. A later invocation
    reads the authoritative head and accepts an already completed migration.
    """
    upgrade = copy.deepcopy(upgrade)
    require(anchor is not None and digest(upgrade) == upgrade_sha256, 'budget-upgrade-review-pin')
    old_limits, old_fees, old_context, new_context = contexts(
        int(rpc.call('eth_chainId'), 16), signer.address, contracts, limits, fees, code_hashes, upgrade, laboratory)
    options = {'anchor': anchor, 'fee_policy': fees, 'code_hashes': code_hashes, 'laboratory': laboratory}
    try:
        queue = TransactionQueue(rpc, signer, path, contracts, limits, **options)
        require(queue.context == new_context, 'budget-upgrade-context-pin')
        return queue
    except InvalidTag:
        # Only an AEAD context mismatch permits trying the explicitly reviewed
        # old context. Other failures never become migration/recovery bypasses.
        pass
    queue = TransactionQueue(rpc, signer, path, contracts, old_limits,
                             **{**options, 'fee_policy': old_fees})
    require(queue.context == old_context, 'budget-upgrade-context-pin')
    from base_fees import BaseFees
    new_fee_calculator = BaseFees(rpc, fees, chain_id=queue.chain)
    previous_context, previous_limits, previous_fees = queue.context, queue.limits, queue.fees
    try:
        with queue._db() as db:
            meta = queue._meta(db)
            # Authenticate every original row before changing any MAC/context.
            # Preserve raw signed bytes, IDs, nonces, reserves, quotes, actual
            # fees and statuses verbatim; no repricing or counter reset.
            def mac(kind, record):
                return signer.authenticate(canonical({'profile': 'nockapp-base-journal-record-v1',
                    'context': new_context, 'kind': kind, 'record': record}))
            for row in list(db.execute('SELECT * FROM submissions')):
                record = {key: row[key] for key in row.keys() if key != 'mac'}
                db.execute('UPDATE submissions SET mac=? WHERE id=?', (mac('submission', record), row['id']))
            for row in list(db.execute('SELECT * FROM fees')):
                record = {key: row[key] for key in row.keys() if key != 'mac'}
                db.execute('UPDATE fees SET mac=? WHERE id=?', (mac('fee', record), row['id']))
            next_meta = {'context': new_context, 'first_nonce': meta['first_nonce'], 'next_nonce': meta['next_nonce']}
            db.execute('UPDATE meta SET context=?,mac=? WHERE singleton=1',
                       (new_context, mac('meta', next_meta)))
            queue.context, queue.limits, queue.fees = new_context, limits, new_fee_calculator
            queue._meta(db)
            # _db commits and seals this whole migration under the new AAD at
            # revision+1, then CASes the same managed head. It never signs/sends.
        return queue
    except Exception:
        queue.context, queue.limits, queue.fees = previous_context, previous_limits, previous_fees
        raise
