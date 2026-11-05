# Reproduce the deployed public index

This is the exact standard-JSON input used for the immutable Base Sepolia index,
including the original flat `PublicCommitmentIndex.sol` source filename. Moving
that filename into a `contracts/` directory changes its Solidity metadata hash.
The source text is the same as the top-level contract snapshot.

Obtain solc 0.8.30 from the Solidity project's official distribution. Verify
its SHA-256 against `deployment.json`, then run:

```sh
python3 verify-build.py --solc /absolute/path/to/solc-0.8.30
```

The checker rejects a different compiler or input, compiles the standard input,
fills the one immutable slot with the original application constructor value,
and compares all 1,010 runtime bytes including metadata. It also checks the
creation bytecode plus constructor argument and the sole mutating ABI entry.
It makes no RPC, wallet or signing request. The public deployment transaction,
contract, runtime hashes and constructor value are in `deployment.json`.

Successful reproduction proves byte-for-byte build correspondence. It does
not prove bug-free logic, private authorship, content availability or trusted
RPC correctness. The index accepts commitments from anyone; inclusion alone
never establishes validity. Clients verify exact offchain bundles independently.
The only mutating function is `submit(bytes32)`: no administrator, proxy,
pause, removal, replacement or renumbering entry exists in this bytecode.
