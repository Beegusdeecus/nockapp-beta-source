# Reproduce the pinned Rust workers

The five authored/renewal/legacy/domain/Nitro-interface workers were rebuilt in
fresh output directories from these scoped sources. All five matched the
packaged binary SHA-256 values. These are clean builds on the recorded host,
not a claim that a second independent machine or the whole EIF was rebuilt.
The authorship rebuild also verified public No.1 and rejected changed text.

## Inputs

Use the exact public release commit and PUBLIC-SOURCE-MANIFEST.json. The
complete composed crate layout is under native-source/reproduced-runtime-v1/.
Its credx dependency and license are included. The NSM API source and notices
come from the pinned AWS commit 4bf743e17f9b4174cc16a4ed743086ca6e541405.
Cargo.lock files pin registry dependencies and their checksums.

Use nightly-2026-04-03 and the exact rustc/cargo hashes in
build-environment.json. The recorded build host used GCC15.2.0, binutils2.46
and glibc2.43; compiler/linker/runtime file hashes are included there. A
different build host can produce different ELF bytes. The Ubuntu24 runtime
installation has separate requirements in installer/ubuntu24/PREREQUISITES.txt;
running the packaged application does not require this compiler environment.

Prime a separate public crates.io cache using the locked manifests and this
toolchain before offline building. Do not use a credential-bearing private
registry. The offline driver mounts only the src/cache/index directories named
index.crates.io-* and never mounts Cargo credentials/configuration or your
private home. Obtain dependency sources through their pinned upstream
distributions; the cache itself is not redistributed in this source release.

## Build

From a Linux build environment matching the recorded hashes, with a working
unprivileged bubblewrap sandbox:

```sh
python3 build-reproduction/build-workers.py   --release-root /absolute/path/to/this/release   --toolchain /absolute/path/to/nightly-2026-04-03-toolchain   --cargo-registry /absolute/path/to/public-cargo-cache/registry   --workspace /absolute/new/empty/worker-build   --worker author
```

Repeat with a new workspace for renewal, domain, nsm and count. The driver
verifies release member hashes and compiler inputs, reconstructs the original
absolute paths only inside its isolated namespace, disables network access,
mounts source/caches read-only and writes only the new workspace. It uses
locked offline Cargo and compares the resulting binary with the pinned hash.
It never installs a binary, opens a NockApp identity or starts an enclave.

The count build deliberately overlays exactly five original source files from
native-source/legacy-count-v2/ onto the composed tree. The retained older count
executable was built before later shared authorship additions. The newer count
source is needed by other workers and does not reproduce that legacy binary;
never reinterpret old proofs or replace its source version silently.

## Image scope

The current approved image remains the EIF and measurements in the manifest's
current issuer fields. A separate offline experiment matched all 1204 filesystem
entries' payloads/modes, including all 70 project source members and four rebuilt
enclave workers, to that image. AWS/OS/SDK runtime materials were pinned and
reused. Bootstrap CPIO matched exactly. Application CPIO ordering/metadata
still differ, so no whole-EIF independent source-build claim is made.
See evidence/approved-image-filesystem-reconstruction-v1.json.

The Ethereum index has its separate exact compiler/input/constructor checker
under contracts/deployed-base-sepolia-v1/. The Go prepaid worker's previously
published scoped source/build instructions remain under native-source/prepaid/.
No compiler result establishes bug-free cryptography, AWS authorization,
protected disaster recovery, operator-independent key confinement or complete
two-client live beta acceptance.
