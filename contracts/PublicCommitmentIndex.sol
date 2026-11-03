// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

/// Permissionless SHA-256 commitment log. Inclusion is NOT proof validation.
/// No caller, UUID, thread hint or issuer can reserve another bundle's identity.
/// Canonical numbers identify exact bytes; clients establish their meaning.
contract PublicCommitmentIndex {
    uint256 public constant INDEX_VERSION = 1;
    bytes32 public immutable application;
    uint64 public nextPostNumber = 1;

    struct Record {
        uint64 number;
        uint64 blockNumber;
        uint64 indexedAt;
    }
    mapping(bytes32 => Record) public records;
    mapping(uint64 => bytes32) public bundleHashes;
    event Indexed(bytes32 indexed bundleHash, uint64 indexed postNumber, uint64 indexedAt);

    constructor(bytes32 app) {
        require(app != bytes32(0), "application");
        application = app;
    }

    /// Any fee payer may submit. A copied exact bundle resolves to the SAME No.
    /// No signature or claim supplied by the fee payer conveys authorship.
    function submit(bytes32 bundleHash) external returns (uint64 number) {
        require(bundleHash != bytes32(0), "bundle-hash");
        number = records[bundleHash].number;
        if (number != 0) return number;
        require(nextPostNumber < 2**53 && block.number <= type(uint64).max
            && block.timestamp <= type(uint64).max, "record-limit");
        number = nextPostNumber++;
        records[bundleHash] = Record(number, uint64(block.number), uint64(block.timestamp));
        bundleHashes[number] = bundleHash;
        emit Indexed(bundleHash, number, uint64(block.timestamp));
    }
}
