// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;
import "./PrepaidRefundVault.sol";

/// One reviewed setup transaction; no callable deployment or spending method.
contract DeployFundedRefundVault {
    address public immutable vault;
    constructor(bytes32 parameters, address purchase, address authority, uint256 price, uint256 count) payable {
        require(msg.value == price * count, "exact-reserve");
        PrepaidRefundVault created = new PrepaidRefundVault(parameters, purchase, authority, price, count);
        vault = address(created);
        (bool funded,) = payable(address(created)).call{value: msg.value}("");
        require(funded && address(created).balance == msg.value, "reserve-funding");
    }
}
