# Protocol reference for the published beta candidate

This describes the implementation snapshots in source commit `b03cb625babde2f5fda8ee440524abfcb33954a9`. It is an implementation reference, not a cryptographic audit or completed live-acceptance claim. `PUBLIC-SOURCE-MANIFEST.json` identifies exact source bytes. Profile identifiers, domain separators, strict schemas and pinned verifier versions are part of the protocol; a similarly named older profile must not be reinterpreted.

| Layer | Profile/version | Authoritative implementation |
| --- | --- | --- |
| Complete public bundle | `nockapp-public-discussion-bundle-v5` | `components/browser-client/rootfs/opt/nockapp/research/zkid/public_bundle_v5.py` |
| Exact post and authorship | `nockapp-post-core-v5` | `authorship_v5.py` in the same directory |
| Historical badge display | `nockapp-public-verifier-v6` | `indexed_authorship_v6.py`, `public_reader_v6.py` |
| Hidden-date credential evidence | `nockapp-hidden-renewal-evidence-v3` | `renewal_evidence_v3.py`, `renewal_policy_v3.py` |
| Blind ticket | `nockapp-ticket-rsabssa-sha384-pss-randomized-v1` | `native-source/prepaid/ticket-crypto/ticket.go` |
| Ticket spend journal | `nockapp-ticket-publication-ledger-v2` | `components/prepaid-backend/rootfs/opt/nockapp/research/zkid/ticket_publication_queue_v2.py` |
| Immutable index | `INDEX_VERSION = 1` | `contracts/PublicCommitmentIndex.sol` |

Client installation profile v7 adds refund configuration. It does not turn the public bundle into a new wire version. Module names below refer to the component snapshots, not an unpinned development checkout.

## Canonical bytes and commitments

For schema-valid values, `C(value)` is the ASCII byte output of Python `json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)`. `H(value)` is lowercase hexadecimal SHA-256 of `C(value)`. This is the application's explicit encoding, not a claim to implement another general-purpose JSON canonicalization standard. Parsers reject duplicate object keys and enforce type, nesting and size limits. Public bundles must decode and re-encode to exactly the original bytes.

A complete bundle is `{unsigned, authorship}`. `unsigned` has exactly `profile`, `encoding`, `core`, `author` and `evidence`. The core contains the application/chain/contract/submission context, post text and metadata, root-thread reference, selected historical references and disclosure choices. `author` contains the exact-post and logical-post group points. Evidence contains exactly `wallet`, `followers` and `history`, each null or canonical base64 of opaque evidence bytes.

The complete encoded bundle is limited to 65,536 bytes. Decoded evidence limits are 4,096 bytes for wallet authorization, 32,768 for follower evidence and 16,384 for historical authorship; these individual maxima do not enlarge the complete-bundle limit. The index commits to `0x || SHA256(complete_bundle_bytes)`, including the final authorship proof. Whitespace changes, changed Unicode encodings or later evidence substitutions cannot preserve that commitment.

## Private authorship and selected history

The local authorship secret controls the identity. Neither Twitter enrollment nor a MetaMask address is required to create it. The native worker derives two scoped group points from that secret:

- The exact scope hashes the entire validated core under `nockapp-exact-post-scope-v5`.
- The logical scope hashes chain, application, contract and post UUID under `nockapp-logical-post-scope-v5`.

The final common-secret proof is checked against both expected points and the digest of `{profile: nockapp-final-authorship-context-v5, unsigned: ...}`. Thus it binds the exact core, disclosure choices and opaque evidence together. The logical point identifies retries of the same author's logical record; it is not a permanent identifier shared by distinct post UUIDs. An arbitrary UUID or fee-payer address does not establish authorship.

Attached historical authorship uses `nockapp-attached-historical-authorship-v5`. The reader first resolves each selected original through public finalized inclusion, exact bytes and its original authorship proof. A common-secret proof then relates up to 15 selected originals and the new post's exact author point. Its context includes the new core hash, new author and selected canonical record references. Original indexing times must not be later than the new record. Copying a certificate cannot satisfy this new proof. Only explicitly supported authored v4/v5 originals qualify; older unbound records do not acquire retrospective authorship. See `historical_authorship_v5.py`.

Portable recovery preserves the same secret. A replacement secret cannot inherit these proofs. Restoring that secret alone does not reconstruct missing issuer-signed credentials, lost tickets, drafts or public content.

## Independent optional disclosures

Both disclosure selections default off. The bundle envelope, including allowed evidence encodings and size bounds, must be well formed. Mandatory content, hash, context and authorship checks precede optional proof-verification branches. Mandatory failure must remain an invalid/unavailable canonical record. A failed optional branch is omitted independently, without rewriting the bundle, blocking valid authored text or inventing a badge.

Wallet evidence uses `NockAppPostAuthorizationV5` EIP-712 data. Its domain binds chain and verifying contract; its message binds application, core hash, exact and logical author hashes, follower/history evidence hashes, nonce and authorization times. The window is exactly 60 seconds and must contain canonical indexing time as `created_at <= indexed_at < expires_at`. The claimed public address must verify the signature. The final authorship proof binds the resulting wallet envelope as part of `unsigned`. A later signature cannot retroactively change an already committed record or establish original wallet authorization. See `wallet_authorship_v5.py`.

For hidden-date follower evidence, the issuer obtains authenticated provider responses inside the approved enclave and signs a holder-bound credential. The source is TwitterAPI.io; client-reported counts are insufficient. Renewal requires a fresh public challenge. The policy defines six **calendar** months in UTC, preserving time of day and clamping a day past the target month's end to that month's last day; it is not a fixed 180-day interval.

The public proof binds the same exact author, selected strict threshold and indexing-time canonical issuer snapshot. It proves `signed_count > selected_threshold` and hidden credential validity covering a public 60-second presentation window containing indexing time. The implementation checks `issued_at <= window_start <= indexed_at < window_end <= renew_by`. Credential issuance and renewal/expiry dates and the exact count remain hidden; the presentation window and Base indexing timestamp are public. The supported count/threshold range is bounded, and a threshold with no greater supported count cannot produce a valid badge.

Verifier v6 evaluates eligibility against the issuer accumulator/snapshot at indexing. Later expiry, revocation or replacement does not remove a previously qualifying historical badge. Explicit legacy date-disclosing evidence remains version-labelled; it is not silently relabelled as hidden-date evidence. See `renewal_evidence_v3.py`, `indexed_authorship_v6.py`, `public_issuer_views.py` and the issuer's `renewal-crypto/src/main.rs`.

## Blind ticket purchase and redemption

The ticket primitive uses CIRCL v1.6.4's fixed RSABSSA-SHA384-PSS-Randomized profile from [RFC 9474](https://www.rfc-editor.org/rfc/rfc9474.html), RSA-3072, exponent 65537 and the profile's 48-byte PSS salt. The public key must be canonical DER SubjectPublicKeyInfo. These checks do not prove honest modulus generation. Clients pin one operator-wide offer/key rather than accept a different key or tagging parameters per buyer.

Let `P` be the 32-byte hash of the complete public offer manifest and `S` a fresh 32-byte client CSPRNG serial. The message is:

```text
"nockapp-prepaid-ticket-v1\0" || P || S
```

Randomized preparation adds the RFC's 32-byte prefix. The client blinds the prepared message and durably encrypts its pending request **before paying**. Only the blinded pack goes to the paid signer. The prepared message, serial and blinding-recovery tape must not be added to the public purchase request or public post bundle.

The Python pack schema is exactly `{profile, parameters, blinded}`. Pack size and the shared public key, application, chain, contract runtime pins, price, deadlines, gas/fee limits and refund policy are bound through the pinned offer. A pack commitment is SHA-256 of `"nockapp-ticket-paid-pack-v1\0" || C(pack)`. Purchase transactions expose their paying wallet and pack commitment. The signer confirms the exact transaction, price, calldata, event, contract runtime and inclusion in the configured RPC's finalized chain view before issuance. A supplied receipt or `paid: true` flag is not enough. See `ticket_offer_v1.py` and `ticket_payment_v1.py`.

Finalization reconstructs CIRCL's state by replaying a versioned, locally encrypted randomness tape, checks the regenerated blinded request and verifies the resulting signature over the stored prepared message. This recovery format is implementation-specific; Go and CIRCL versions remain pinned.

A redeemed token contains exactly `{profile, parameters, prepared, signature}`. Both the signature and the embedded parameter hash must verify. Its one-use identifier is:

```text
SHA256("nockapp-ticket-nullifier-v1\0" || P || S)
```

The randomized preparation prefix is deliberately excluded: repeating one serial with another prefix must not create another spend identity. The spender atomically binds that identifier to one exact bundle hash. Same-ticket/same-bundle retries recover the saved operation; another bundle is rejected. Exact already-indexed bytes can resolve without consuming a fresh ticket. Storage happens before normal indexing.

The worker persists the exact signed transaction bytes, nonce and hash before broadcast and resumes that operation after uncertainty. A timeout is not authority to replace a ticket or recreate a journal. Immutable encrypted S3 revision slots, conditional writes, authenticated journal state and configured chain anchors support recovery; actual IAM, deletion/version/lifecycle protection, backup procedures and concurrent-writer enforcement remain deployment requirements. The code still labels generic production antirollback as unproven. Local fixture success does not remove that deployment gate.

Refunds concern a whole **unissued** pack under `unissued-only-durable-decision-v1`, not arbitrary unused tickets after issuance. The original payer authorizes the exact pack/payment/offer and durable cancellation purpose. Issuance-versus-refund must have one durable decision before a payout is queued. The refund worker verifies the original finalized payment/payer; the separate vault additionally bounds its authority and total principal. These controls do not make prepaid custody self-custodial. See `ticket_issuance_v1.py`, `ticket_refund_payout_v1.py` and `contracts/PrepaidRefundVault.sol`.

## Public index, storage and independent reading

`PublicCommitmentIndex.submit(bytes32)` accepts any fee payer and a nonzero complete-bundle hash. It assigns the next canonical number to a new hash and returns the existing number for the same hash. It stores the indexing block and timestamp. It has no proof-validation branch, administrator pause, deletion, replacement or proxy upgrade. Inclusion establishes ordering/commitment, not valid authorship, a truthful badge or a relationship to the payer.

Readers obtain canonical finalized inclusion and exact public bundle bytes, then verify context, authored content and each evidence branch locally. They must preserve invalid/unavailable numbered records instead of interpreting missing content as empty history. Public object hashes authenticate bytes, not availability or proof validity. Chain hashes cannot restore lost text. Mirrors and archives must retain exact bytes; imported material requires independent verification.

Positive verification caches are bounded and tied to content hash, verifier/trust version, chain anchor and evidence dependencies. Historical issuer snapshots are public evidence, not a private issuer-database lookup or a service verdict. The configured RPC remains trusted for its chain/finality view; this implementation is not a consensus light client.

## Trust boundaries and remaining acceptance

The authorship/holder secret belongs on the user's computer. The host ticket-signing key, publication gas key, refund key, TLS CA and Nitro credential-issuer key serve distinct purposes. Host process separation is not a claim that the host operator cannot correlate network activity. Blind signatures do not conceal IP addresses, timing, small anonymity sets or a voluntarily disclosed wallet address.

Attestation measures an executable under AWS/hardware assumptions. It does not prove bug-free code, truthful provider data or correct administrator/state recovery boundaries. Final issuer-key administrator confinement, full image reconstruction/provenance, complete live payment/source acceptance, full disaster recovery, capacity/cost evidence and two complete independent Ubuntu workflows remain open gates. This protocol reference does not mark any of them complete.

## Relay payment and recovery update (current v2 snapshots)

For the current payment/refund implementation, use `prepaid-backend-relay-v2` and `browser-client-relay-v2`; the earlier sections describe the retained historical snapshots. A canonical `PackPaid` event from the pinned purchase contract binds the actual payer, pack and exact price. An outer transaction may be sponsored or delegated: its sender, destination and input alone are not the inner purchase identity. Refund authorization and destination use the authenticated event payer, never a presumed relayer.

The client retains its exact purchase intent. A bounded contract-paid-slot search can recover a wrapped transaction whose wallet reply was lost. The helper checks saved pack, payer and canonical chain anchor, then compares the saved intent under lock. An advanced EOA nonce alone cannot rule out a delayed relay: closure also requires the immutable purchase deadline to be finalized and the pack still unpaid. An uncertain payment is never automatically resent, cleared or reused. The versioned issuer budget migration preserves authenticated journal history, first nonce, existing fees, signed bytes and reservations; changing its cumulative cap requires explicit owner approval and completes before boot acknowledgement. No reset is an acceptable recovery strategy.


## Installed forum and recovery update (2026-11-05 AEST)

The current frontend is `80c62c68f38acb148ad73ecb2ab4b2d0c4231d77`. It opens a canonical public feed, automatically verifies visible posts and independent badges, opens bookmarkable full-thread tabs and keeps unavailable records explicit. Publication progress and automatic read-only recovery preserve the exact pending content; timeouts never authorize another signature, submission or ticket reassignment. A failed selected follower attachment stops before submission.

`evidence/current-source-snapshots-v3.json` pins the installed browser-native `99d9580e…c138` snapshot and separate terminal backup diagnostics `9fd21583…d6cfa`. The new component directories preserve exact frozen source versions; earlier directories remain historical. Installer metadata fixes stale source pins without changing runtime code; the Ubuntu24 variant additionally pins its bwrap binary. Do not substitute target-specific installers on another operating system. These source snapshots contain no configured bindings, private state or runtime executables.

Authorship backup exports the existing local authorship secret encrypted with a user passphrase (16–1024 UTF-8 bytes); restore preserves the identity and refuses unauthorized replacement. MetaMask login alone does not back up this separate secret; wallet-based recovery is not implemented. Credentials and prepaid tickets are separate. Selected follower proofs retain the existing 60-second indexing-time window. A 15-second local submission margin does not guarantee inclusion before expiry; historical expired optional proofs cannot be repaired by editing committed content.

The installed frontend suite passed 300 cases with one optional skip. Two Ubuntu24 guests verified public posts and restored a synthetic authorship backup, but they share a host and did not perform two complete live signup/payment/publication workflows. The original issuer EIF, relay runtime and trust requirements remain unchanged. Whole-image reproducibility, unattended reboot/disaster recovery, antirollback, final issuer administrator confinement and full beta acceptance remain open.


## Parent startup diagnostics (2026-11-05 AEST)

`components/parent-startup-diagnostics-v1/` retains the updated parent supervisor and parent test source. `evidence/parent-startup-diagnostics-v1.json` pins fixed failure-stage/reason/class filtering,41local fixture checks, actual isolated-rootfs admission and successful parent-only restart. Private inputs and arbitrary exception text are excluded. Enclave image, keys, budgets and durable startup/retry rules are unchanged. A subsequent EC2 reboot reproduced a failure during protected bootstrap; it remains under diagnosis. This publication does not claim reboot recovery or completed beta acceptance. Complete companion test fixtures/native-tool dependencies are not redistributed by this update; full standalone build/test provenance remains an open gate. Older runtime snapshots remain exact historical versions.


## Parent readiness recovery and safe bootstrap phases (2026-11-05 AEST)

`components/parent-startup-recovery-v2/` preserves the updated host supervisor/bootstrap source and updated parent tests. Readiness now checks the exact owned enclave before and after attested admission; confirmed absence reaches existing guarded recovery instead of waiting for the full readiness timeout. Observation errors are never treated as absence. Bootstrap diagnostics distinguish channel, credential acquisition, caller identity, selected identity records, envelope validation and delivery readiness using fixed labels only. Private data and exception text are not logged. Original delivery/intent/retry fences, measured image, keys and budgets remain unchanged.52local fixture checks and actual isolated-rootfs import/admission pass. A real reboot exposed the wait-after-exit bug and the monitor detected a later exit; the original bootstrap rejection and complete unattended reboot acceptance remain unresolved. Complete fixture/native build dependencies are still an open distribution/provenance gate.


## Ticket preflight and unchanged publication recovery (2026-11-05 22:08 AEST)

Frontend `149b3114f42ac1fd221c8f67f6e790d1c0d9e3b5` checks ticket availability before preparing a new publication. Client-native manifest `279101a63d392f2e7d6d482576cc7ea63fb521b7d2a42e9a53ee550b2f160924` exposes only fixed recovery conditions and a status derived from saved public proof evidence. The normal 60-second indexing-time follower window and 15-second local margin remain unchanged. A separately approved recovery can publish the same previously signed bundle even after its optional follower proof expires. It does not refresh proofs, sign replacement bytes or release/reassign tickets. The independent reader still validates mandatory authorship and omits optional badges invalid at canonical indexing. Automatic recovery only reads status; it never signs or submits. Zero unassigned tickets alone does not establish whether a saved bundle already has a bound ticket.

The new component snapshot and `evidence/publication-recovery-source-v1.json` retain exact provenance and test scope. Local crypto/EVM and browser fixtures plus read-only live public admission do not establish successful owner recovery or full beta acceptance. No server/image/IAM/issuer-key change was needed. Earlier snapshots remain historical; complete independent build inputs and two complete fresh Ubuntu workflows remain open.


## Fifty tickets in one atomic wallet payment (2026-11-05 23:32 AEST)

Frontend `8c7a19166c4c5c93bdad269b2964d67d7bd53404` and native client manifest `6bb64dcd6b061bd7dee3b52083403c2b9e955eb9d2f2d319e9336f1587e24a0e` support 50 tickets through one EIP-5792 atomic wallet transaction containing 25 calls to the existing two-ticket contract. The shared offer, blind-signing key, ticket format, ticket price, payment contract and refund policy stay unchanged. The app checks enabled atomic support, requests atomic execution, and never silently upgrades an account or falls back to sequential payments. All blind inputs are encrypted before dispatch. Native one-shot admission precedes the wallet call; a lost reply cannot authorize a second send. Finalized public contract events for all 25 packs and the original payer are checked before import. Each existing pack is verified and imported atomically. A crash between wallet import and bulk-cursor persistence recovers without duplicate tickets. The six prior assignments in the labelled fixture remain unchanged. Unissued-pack cancellation retains the existing separate wallet authorization, issue-or-refund fence and capped shared reserve; bulk import can pause for that existing refund flow.

Publication backend manifest `4f9fde4006c3fda418c58105259c7790c5f69aee0309a37486209a0ab6fe8f71` uses an explicit new budget deployment profile:64 lifetime submissions,0.00128 ETH execution reserve,0.004 ETH total fee/funding caps. Per-transaction gas and fee ceilings are unchanged. The original protected boot config remains byte-for-byte intact as the sealed-key context; a separately pinned outer plan selects the new cumulative limits. The same authenticated encrypted journal preserves all ticket bindings, signed bytes, statuses, nonces and prior charges. Migration is one atomic managed-head update, checks headroom for 50 publications and the incoming payment, resumes the new context after a lost commit reply, and never initializes an absent journal or signs/broadcasts a transaction. Only the publication worker was restarted; issuer image, IAM, payment/refund workers, keys and other service authorities remain unchanged. Older source snapshots are retained.

Checks:71 purchase/recovery/refund/native installation cases,20 backend/migration cases,313 browser cases with one optional skip, and isolated frozen/live public admission. These are fixture and read-only operational checks; actual owner MetaMask payment and 50-ticket import remain pending. Full beta acceptance and whole-image independent reproducibility remain open.


## Current checkout and exact index build (2026-11-05 23:58 AEST)

Frontend `363a0f2167db0e55cbc8d6ed1f3c693de0089b2c` distinguishes the historical imported-ticket receipt from current available inventory. Reopening a completed purchase after spending its tickets does not offer a second payment. The full browser check passed 313 cases with one optional skip. No wallet or private-holder action was performed. Actual owner 50-ticket payment/import remains pending.

`contracts/deployed-base-sepolia-v1/` now provides the original compiler input, public constructor/deployment values and a standalone pinned-solc checker reproducing all 1,010 deployed runtime bytes including metadata, plus the original creation bytecode. See its README. This closes the exact index build recipe gap; it does not establish whole-enclave reproducibility or complete live beta acceptance. Earlier component snapshots remain unchanged.
