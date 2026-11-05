# NockApp beta source snapshots

Source and test vectors for the Ubuntu public-beta implementation. This is a release-candidate source publication, not an announcement that the beta has passed live acceptance.

The installed browser client, proposed paid-client update, terminal client, payment backend, one-time journal setup tool and Nitro issuer keep separate directories under `components/`. Identical-looking modules from different versions are not silently merged. `evidence/runtime-source-index.json` ties each exported source byte to its frozen runtime manifest. `PUBLIC-SOURCE-MANIFEST.json` indexes this entire source release. No operator configuration, credentials, user records, prebuilt executable or private repository history is included.

The earlier published Nitro issuer image hash is `b618f8cdb92b59f984987578fadddb9c53d5deb779db2c311d71a8c71e48f6b3`; backend manifest `88f67f28833399ffe7eb93df3f25e69e32dcc32083a6145e796603995c605dc6`; installed browser manifest `df0f08af80d525a5464e1f1b9c0d3e8fa2359a5c3733c5319ac795fa10d92acd`. The paid client candidate and management tool are explicitly labelled. A source snapshot or manifest is not hardware attestation. Live deployment and acceptance evidence remains separate.

Read [the implementation protocol reference](PROTOCOL.md) for exact encodings, post/credential bindings, ticket spend/recovery semantics and trust boundaries.

## Build and test

For the extension, use Node >=22.12.0 in `frontend/`, run `npm ci`, install the pinned Playwright Chromium and ordinary Ubuntu browser dependencies, then run `NOCKAPP_HELPER_INSTALLER_PATH=../test-support/legacy-source-helper/tools/install-x-helper.py npm run check`. The explicit helper path supplies the retained stage-1 feasibility helper for one isolated legacy IPC test; it does not configure the beta issuer or read a live account. `package-lock.json` is authoritative; do not upgrade dependencies during reproduction. Tests use synthetic fixtures and isolated browser profiles. Optional browser scenarios may be skipped as labelled by the suite.

`contracts/` contains the four dependency-free Solidity contracts and pinned compiler settings/hash. Compile with solc 0.8.30 and the included standard-JSON settings. Constructor immutable values select deployment-specific runtime code; a runtime template is not a deployed-code pin.

`native-source/authorship/` contains the admitted Rust crate sources and locked public credx dependency. Preserve its directory layout and Cargo.lock. The retained successful build used nightly-2026-04-03, `cargo build --locked --offline --jobs 2 --manifest-path authorship-crypto/Cargo.toml --target-dir /absolute/new/empty/target` from the appropriate source root. A fresh machine first needs the pinned toolchain and exact locked dependencies. `native-source/prepaid/ticket-crypto/` contains the pinned Go ticket implementation and tests. Use its go.mod/go.sum and Go 1.27.3. From that directory run `go test ./...` and `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 go build -mod=readonly -trimpath -buildvcs=false -o /absolute/new/output/nockapp-ticket-worker-v1 ./cmd/ticket-worker`. Dependency source/license notices are retained where included by the admitted snapshots.

The component sources, Dockerfile and runtime inventories document the measured implementation. This release does not yet supply every dependency/runtime/build input needed to independently reconstruct the entire EIF or every frozen capsule. Repeat archive checks do not prove independent source compilation. No whole-image reproducibility claim is made.

## Security and trust

Authorship is bound to exact public content and context; optional Ethereum and follower disclosures are independent. Public-chain timestamps remain visible. Blind tickets separate purchase from redemption cryptographically; they do not hide IP addresses, timing, small anonymity sets or co-hosting correlations. The prepaid operator can refuse service or lose custody funds. Public storage availability is not guaranteed by an onchain hash.

Nitro attestation depends on measured code correctness, AWS/hardware, authenticated source observations and protected state/recovery. It does not prove truthful source data or bug-free software. Final issuer administrator confinement, complete live prepaid acceptance, full disaster recovery and two complete independent Ubuntu workflows remain release gates. Existing third-party license/notice files are preserved; this snapshot adds no blanket relicensing grant.

## Current installed source snapshots (2026-11-04 AEST)

`evidence/current-source-snapshots-v2.json` pins the current issuer, payment backend and browser client. Their separate `*-v2` component directories retain exact frozen versions; earlier component directories remain historical. The issuer EIF is `eb8e41828681be159ff7d37e676018273b2ea57bb452fd0bcb223b9d4d61f7ee`, backend manifest `306404adf7aa58a0761d41d9fa73c8cddfc9f649414d8fbe09f662f0ba4016a7`, browser manifest `20d10e3bcab46b6311d681c51269e82e5d4c3d5446a348bbcd1eee724d66f182`. Frontend commit `64980a5` simplifies writing, local-first loading and explicit recovery after uncertain requests. Operator configurations and user records are excluded. These pins do not assert completed beta acceptance or whole-image independent reproducibility.

Verification UI follow-up `6a589c737b406c4d50745b119060181184917e03` presents confirmed Post challenge / Check tweet / Finalize credential checkpoints, indeterminate requests and finality guidance without a fabricated ETA. It opens cancellation for retired attempts and places fresh consent beside the tweet-check button. Only credential-saved completes the bar. Issuer and ticket runtime pins above remain unchanged.


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
