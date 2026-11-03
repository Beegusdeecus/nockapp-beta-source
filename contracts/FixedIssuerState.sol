// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

/// Fixed-authority issuer state: normal updates, no governor or authority setter.
/// A lost/compromised updater requires a new deployment. Legacy state is unchanged.
/// The updater is trusted to implement issuance policy. Hashes do NOT provide DA.
contract FixedIssuerState {
    address public immutable updater;
    bytes32 public immutable definition;
    uint256 public revision;
    bytes32 public ciphertextHash;
    bytes32 public registryHash;
    uint256 public registrySequence;
    bool public initialized;
    uint256 public bootEpoch;
    event Updated(uint256 indexed revision, bytes32 ciphertextHash,
                  bytes32 registryHash, uint256 registrySequence, bytes publicRegistry);

    constructor(address writer, bytes32 issuerDefinition) {
        require(writer != address(0) && issuerDefinition != bytes32(0), "configuration");
        updater = writer; definition = issuerDefinition;
    }


    function head() external view returns (uint256, bytes32, bytes32, uint256, bool) {
        return (revision, ciphertextHash, registryHash, registrySequence, initialized);
    }

    function update(uint256 expectedRevision, bytes32 expectedCiphertext, bytes32 nextCiphertext,
                    uint256 sequence, bytes calldata publicRegistry) external {
        require(msg.sender == updater, "updater");
        require(bootEpoch == 0, "lease-required");
        _update(expectedRevision, expectedCiphertext, nextCiphertext, sequence, publicRegistry);
    }

    function beginLease(uint256 expectedEpoch, uint256 expectedRevision, bytes32 expectedCiphertext,
                        bytes32 nextCiphertext, uint256 sequence, bytes calldata publicRegistry) external {
        require(msg.sender == updater && expectedEpoch == bootEpoch, "lease-conflict");
        bootEpoch++;
        _update(expectedRevision, expectedCiphertext, nextCiphertext, sequence, publicRegistry);
    }

    function updateLeased(uint256 epoch, uint256 expectedRevision, bytes32 expectedCiphertext,
                          bytes32 nextCiphertext, uint256 sequence, bytes calldata publicRegistry) external {
        require(msg.sender == updater && epoch == bootEpoch && epoch > 0, "lease-conflict");
        _update(expectedRevision, expectedCiphertext, nextCiphertext, sequence, publicRegistry);
    }

    function _update(uint256 expectedRevision, bytes32 expectedCiphertext, bytes32 nextCiphertext,
                     uint256 sequence, bytes calldata publicRegistry) private {
        require(expectedRevision == revision && expectedCiphertext == ciphertextHash, "state-conflict");
        require(nextCiphertext != bytes32(0) && nextCiphertext != ciphertextHash, "ciphertext");
        require(publicRegistry.length > 0 && publicRegistry.length <= 16384, "registry-size");
        bytes32 nextRegistry = sha256(publicRegistry);
        if (initialized) {
            require(sequence == registrySequence || sequence == registrySequence + 1, "sequence");
            // Private sessions/reservations may advance revision without changing registry.
            require((sequence == registrySequence) == (nextRegistry == registryHash), "registry-transition");
        }
        initialized = true; revision++; ciphertextHash = nextCiphertext;
        registryHash = nextRegistry; registrySequence = sequence;
        emit Updated(revision, nextCiphertext, nextRegistry, sequence, publicRegistry);
    }
}
