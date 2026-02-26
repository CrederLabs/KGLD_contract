// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/proxy/Proxy.sol";

contract CommodityTokenProxy is Proxy {
    // ====================
    // EIP-1967 Slots
    // ====================
    // bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
    bytes32 private constant _IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    // ====================
    // Constructor
    // ====================
    /// @param _logic initial implementation contract address
    /// @param _data  call data for initialization
    constructor(address _logic, bytes memory _data) payable {
        require(_logic != address(0), "UUPSProxy: logic is zero");
        _setImplementation(_logic);

        if (_data.length > 0) {
            // Call the initialization function
            (bool success, ) = _logic.delegatecall(_data);
            require(success, "UUPSProxy: initialization failed");
        }
    }

    // ====================
    // EIP-1967 Functions
    // ====================
    function _getImplementation() internal view returns (address impl) {
        bytes32 slot = _IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
        }
    }

    function _setImplementation(address newImplementation) private {
        bytes32 slot = _IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImplementation)
        }
    }

    function _implementation() internal view override returns (address) {
        return _getImplementation();
    }

    function getImplementation() external view returns (address impl) {
        return _getImplementation();
    }

    // ====================
    // Receive
    // ====================
    receive() external payable {
        super._fallback();
    }
}
