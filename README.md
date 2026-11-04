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
