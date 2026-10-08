// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @notice ERC-1967 proxy; upgrade authorization lives in the Treasury implementation.
contract TreasuryProxy is ERC1967Proxy {
    error InitializationRequired();

    /// @param implementation Initial Treasury implementation.
    /// @param data Encoded initialize(roleRegistry, policyRegistry) call executed at deployment.
    constructor(address implementation, bytes memory data) ERC1967Proxy(implementation, data) {
        if (data.length == 0) revert InitializationRequired();
    }

    function getImplementation() external view returns (address) {
        return _implementation();
    }

    receive() external payable {
        _fallback();
    }
}
