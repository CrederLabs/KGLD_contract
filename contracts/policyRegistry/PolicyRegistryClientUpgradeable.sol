// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {RoleRegistryClientUpgradeable} from "../roleRegistry/RoleRegistryClientUpgradeable.sol";
import {IPolicyRegistry} from "./IPolicyRegistry.sol";
import {IRoleRegistryAwarePolicyRegistry} from "./IRoleRegistryAwarePolicyRegistry.sol";

/// @title Shared-policy-registry integration for proxy-based consumers.
/// @notice Initialize RoleRegistryClient first, then this module in the same child initializer.
/// @dev The registry is set once; replacement requires a new implementation with an explicit migration.
abstract contract PolicyRegistryClientUpgradeable is RoleRegistryClientUpgradeable {
    /// @custom:storage-location erc7201:kgold.storage.PolicyRegistryClient
    struct PolicyRegistryClientStorage {
        IPolicyRegistry registry;
    }

    // keccak256(abi.encode(uint256(keccak256("kgold.storage.PolicyRegistryClient")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant POLICY_REGISTRY_CLIENT_STORAGE_LOCATION =
        0xd8356fb2f9cf417242635afb3d5e924e76e0a5c56d76564f2f9d4b6c30956100;

    error InvalidPolicyRegistry(address registry);
    error PolicyRegistryAlreadyInitialized();
    error PolicyRegistryRoleRegistryMismatch(
        address policyRegistry, address expectedRoleRegistry, address actualRoleRegistry
    );
    error PolicyForbids(uint64 policyId, address account);

    /// @notice Records registry installation during a consumer's migration.
    event PolicyRegistryUpdated(address indexed previousRegistry, address indexed newRegistry);

    function __PolicyRegistryClient_init(address registry) internal onlyInitializing {
        __PolicyRegistryClient_init_unchained(registry);
    }

    function __PolicyRegistryClient_init_unchained(address registry) internal onlyInitializing {
        PolicyRegistryClientStorage storage $ = _getPolicyRegistryClientStorage();
        if (address($.registry) != address(0)) revert PolicyRegistryAlreadyInitialized();
        _validatePolicyRegistry(registry);
        $.registry = IPolicyRegistry(registry);
    }

    function policyRegistry() public view returns (IPolicyRegistry) {
        return _getPolicyRegistryClientStorage().registry;
    }

    function isPolicyAuthorized(uint64 policyId, address account) public view returns (bool) {
        IPolicyRegistry registry = policyRegistry();
        if (address(registry) == address(0)) revert InvalidPolicyRegistry(address(0));
        return registry.isAuthorized(policyId, account);
    }

    function _checkPolicyExists(uint64 policyId) internal view {
        IPolicyRegistry registry = policyRegistry();
        if (address(registry) == address(0)) revert InvalidPolicyRegistry(address(0));
        if (!registry.policyExists(policyId)) revert IPolicyRegistry.PolicyNotFound();
    }

    function _checkPolicy(uint64 policyId, address account) internal view {
        if (!isPolicyAuthorized(policyId, account)) revert PolicyForbids(policyId, account);
    }

    function _validatePolicyRegistry(address registry) private view {
        if (registry.code.length == 0) revert InvalidPolicyRegistry(registry);
        address expectedRoleRegistry = address(roleRegistry());
        if (expectedRoleRegistry == address(0)) revert InvalidRoleRegistry(address(0));
        address actualRoleRegistry = address(IRoleRegistryAwarePolicyRegistry(registry).roleRegistry());
        if (actualRoleRegistry != expectedRoleRegistry) {
            revert PolicyRegistryRoleRegistryMismatch(registry, expectedRoleRegistry, actualRoleRegistry);
        }
    }

    function _getPolicyRegistryClientStorage() private pure returns (PolicyRegistryClientStorage storage $) {
        assembly {
            $.slot := POLICY_REGISTRY_CLIENT_STORAGE_LOCATION
        }
    }
}
