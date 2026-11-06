# Same-purchase recovery and wallet state

Apply the five explicit native source replacements over components/browser-migrated-ticket-status-v7. The runtime manifest is inventory only; this is neither a configured installation nor a redistributable native binary package. Frontend sources match the stated commit. All shown tests are synthetic/component checks, not actual owner MetaMask or two-machine beta acceptance.

Recovery retains the original25pack IDs, price, payer, contract and native journal. It uses the wallet's already installed, bytecode-pinned EIP7702 batch implementation in revert-on-failure mode. It does not upgrade the wallet or create replacement packs. If two complete same-ID requests race, the original contract's paid-once checks plus atomic rollback permit at most one full principal payment. A failed duplicate can spend gas. Owner review/approval is always explicit; no automatic wallet resend is permitted. Wallet delegation remains a wallet-controlled trust assumption; a preflight pin does not constrain a separately authorized later account-code change.

Native authorization is durable but is not proof that MetaMask received a request. A separate bounded display history records the dispatch boundary, transaction hash when returned, and explicit rejection. Lost replies remain unknown across reloads. Display data never authorizes issuance or overrides receipt, contract, payer, finality, all-pack, capacity or spending checks. The old different-new-purchase terminal fence remains.

Read-only wallet checks run with short bounded timeouts. An account connection is requested only by explicit Connect, rather than unconditionally during Confirm. Plain provider errors are mapped to safe method/code diagnostics; arbitrary provider text is not shown or persisted. A redundant wallet eth_call is removed; the native fresh exact-call simulation and all25paid-slot checks remain, as do the wallet code/account/nonce/balance/expiry checks before dispatch. Interrupted background checks do not overwrite the current UI step.

Public deployed MetaMask bytecode is a synthetic EVM test input, accompanied by upstream MIT AND Apache-2.0 licenses and provenance notice. Matching a source tag to observed runtime bytes does not establish independent bytecode reproduction.

The real owner's latest wallet failure is not diagnosed solely by these passing checks. Private state stays with the owner. Protected recovery, rollback/concurrency/confinement review, build provenance, cost/capacity evidence and complete independent installed workflows remain release gates.
