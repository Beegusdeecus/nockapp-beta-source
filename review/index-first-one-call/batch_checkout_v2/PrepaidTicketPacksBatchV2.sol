// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

/// REVIEW ONLY: new deployment and versioned client/service integration required.
/// Existing v1 contracts, offers, tickets and uncertain purchases are unchanged.
contract PrepaidTicketPacksBatchV2 {
    uint256 public constant PURCHASE_VERSION = 2;
    uint256 public constant BATCH_PACKS = 25;
    bytes32 public immutable termsHash;
    address payable public immutable recipient;
    uint256 public immutable packPrice;
    uint64 public immutable purchaseBefore;
    mapping(bytes32 => bool) public paid;
    event PackPaid(bytes32 indexed packHash, address indexed payer, uint256 amount);

    constructor(bytes32 terms, address payable receiver, uint256 price, uint64 deadline) {
        require(terms != bytes32(0) && receiver != address(0) && price > 0
            && price <= type(uint256).max / BATCH_PACKS && deadline > block.timestamp, "offer");
        termsHash = terms; recipient = receiver; packPrice = price; purchaseBefore = deadline;
    }
    function buy(bytes32 packHash) external payable {
        require(block.timestamp < purchaseBefore && msg.value == packPrice, "payment");
        _mark(packHash); _forward();
    }
    function buyBatch(bytes32[25] calldata packs) external payable {
        require(block.timestamp < purchaseBefore && msg.value == BATCH_PACKS * packPrice, "payment");
        // All writes roll back if one pack, the value, or forwarding fails.
        // Each pack is marked before any external call, including duplicates.
        for (uint256 i; i < BATCH_PACKS; ++i) _mark(packs[i]);
        _forward();
    }
    function _mark(bytes32 packHash) private {
        require(packHash != bytes32(0) && !paid[packHash], "pack");
        paid[packHash] = true; emit PackPaid(packHash, msg.sender, packPrice);
    }
    function _forward() private {
        (bool sent,) = recipient.call{value: msg.value}(""); require(sent, "recipient");
    }
}
