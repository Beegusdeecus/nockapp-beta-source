// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

/// Fixed-price payment receipts for one publicly pinned ticket offer.
/// Does not sign tickets, validate posts, or administer the public index.
contract PrepaidTicketPacks {
    uint256 public constant PURCHASE_VERSION = 1;
    bytes32 public immutable termsHash;
    address payable public immutable recipient;
    uint256 public immutable packPrice;
    uint64 public immutable purchaseBefore;
    mapping(bytes32 => bool) public paid;

    event PackPaid(bytes32 indexed packHash, address indexed payer, uint256 amount);

    constructor(bytes32 terms, address payable receiver, uint256 price, uint64 deadline) {
        require(terms != bytes32(0) && receiver != address(0) && price > 0
            && deadline > block.timestamp, "offer");
        termsHash = terms;
        recipient = receiver;
        packPrice = price;
        purchaseBefore = deadline;
    }

    function buy(bytes32 packHash) external payable {
        require(packHash != bytes32(0) && !paid[packHash], "pack");
        require(block.timestamp < purchaseBefore && msg.value == packPrice, "payment");
        // Set before forwarding; a callback cannot pay this pack twice.
        paid[packHash] = true;
        emit PackPaid(packHash, msg.sender, msg.value);
        (bool sent,) = recipient.call{value: msg.value}("");
        require(sent, "recipient");
    }
}
