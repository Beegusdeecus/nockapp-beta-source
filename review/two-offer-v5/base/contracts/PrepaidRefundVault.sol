// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// Custodial refund spend boundary. The dedicated authority must independently
/// verify payment and the durable issue-or-refund decision. This contract does
/// not prove that a pack was purchased or that blind issuance was cancelled.
contract PrepaidRefundVault {
    uint256 public constant REFUND_VERSION = 1;
    bytes32 public immutable parameters;
    address public immutable purchaseContract;
    address public immutable authority;
    uint256 public immutable packPrice;
    uint256 public immutable maxRefunds;
    uint256 public immutable principalBudget;
    uint256 public totalRefunded;
    uint256 public refundCount;
    struct Refund { address payer; bytes32 paymentTransaction; uint256 blockNumber; }
    mapping(bytes32 => Refund) public refunds;

    bytes32 private constant DOMAIN_TYPE = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant REFUND_TYPE = keccak256("NockAppUnissuedPackRefundV1(string purpose,bytes32 parameters,bytes32 packHash,bytes32 paymentTransaction)");
    bytes32 private constant PURPOSE = keccak256("Permanently cancel issuance of this paid ticket pack; refund only its original paying wallet");
    event Refunded(bytes32 indexed packHash, address indexed payer, bytes32 indexed paymentTransaction, uint256 amount);

    constructor(bytes32 offer, address purchase, address signer, uint256 price, uint256 count) {
        require(block.chainid == 84532 && offer != bytes32(0) && purchase != address(0)
            && signer != address(0) && price > 0 && price < 2**128 && count > 0 && count <= 4096, "configuration");
        parameters = offer; purchaseContract = purchase; authority = signer;
        packPrice = price; maxRefunds = count; principalBudget = price * count;
    }

    receive() external payable {
        require(address(this).balance + totalRefunded <= principalBudget, "funding-cap");
    }

    function refund(bytes32 packHash, bytes32 paymentTransaction, address payable payer, bytes calldata signature) external {
        require(msg.sender == authority && packHash != bytes32(0) && paymentTransaction != bytes32(0)
            && payer != address(0) && refunds[packHash].blockNumber == 0, "refund-authority");
        require(signature.length == 65 && refundCount < maxRefunds
            && totalRefunded + packPrice <= principalBudget && address(this).balance >= packPrice, "refund-budget");
        bytes32 r; bytes32 s; uint8 v;
        assembly { r := calldataload(signature.offset) s := calldataload(add(signature.offset, 32)) v := byte(0, calldataload(add(signature.offset, 64))) }
        require((v == 27 || v == 28) && uint256(s) > 0
            && uint256(s) <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0, "signature");
        bytes32 domain = keccak256(abi.encode(DOMAIN_TYPE, keccak256("NockApp Prepaid Tickets"), keccak256("1"), block.chainid, purchaseContract));
        bytes32 message = keccak256(abi.encode(REFUND_TYPE, PURPOSE, parameters, packHash, paymentTransaction));
        require(ecrecover(keccak256(abi.encodePacked(hex"1901", domain, message)), v, r, s) == payer, "payer-consent");
        refunds[packHash] = Refund(payer, paymentTransaction, block.number);
        ++refundCount; totalRefunded += packPrice;
        emit Refunded(packHash, payer, paymentTransaction, packPrice);
        (bool sent,) = payer.call{value: packPrice}("");
        require(sent, "payout-failed");
    }
}
