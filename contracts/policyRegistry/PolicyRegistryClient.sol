// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {RoleRegistryClient} from "../roleRegistry/RoleRegistryClient.sol";
import {IPolicyRegistry} from "./IPolicyRegistry.sol";
import {IRoleRegistryAwarePolicyRegistry} from "./IRoleRegistryAwarePolicyRegistry.sol";

/// @title Shared-policy-registry integration for constructor-based consumers.
/// @notice The concrete consumer supplies its RoleRegistry to RoleRegistryClient and
/// its PolicyRegistry to this constructor. Both registries must agree at deployment
/// and their addresses cannot be changed afterward.
abstract contract PolicyRegistryClient is RoleRegistryClient {
    IPolicyRegistry private _policyRegistry;

    error InvalidPolicyRegistry(address registry);
    error PolicyRegistryRoleRegistryMismatch(
        address policyRegistry, address expectedRoleRegistry, address actualRoleRegistry
    );
    error PolicyForbids(uint64 policyId, address account);

    /// @param registry Deployed PolicyRegistry sharing the consumer's configured RoleRegistry.
    /// @dev The final consumer must also invoke RoleRegistryClient(roleRegistry) in its constructor list.
    constructor(address registry) {
        _setPolicyRegistry(registry);
    }

    function policyRegistry() public view returns (IPolicyRegistry) {
        return _policyRegistry;
    }

    /// @notice Queries the configured Registry without treating unknown IDs specially.
    function isPolicyAuthorized(uint64 policyId, address account) public view returns (bool) {
        return policyRegistry().isAuthorized(policyId, account);
    }

    /// @dev Use when storing a policy ID. Built-in policies are accepted by policyExists.
    function _checkPolicyExists(uint64 policyId) internal view {
        if (!policyRegistry().policyExists(policyId)) revert IPolicyRegistry.PolicyNotFound();
    }

    /// @dev Use on a gated execution path after a policy ID has been validated at write time.
    function _checkPolicy(uint64 policyId, address account) internal view {
        if (!isPolicyAuthorized(policyId, account)) revert PolicyForbids(policyId, account);
    }

    function _setPolicyRegistry(address registry) private {
        if (registry.code.length == 0) revert InvalidPolicyRegistry(registry);
        address expectedRoleRegistry = address(roleRegistry());
        address actualRoleRegistry = address(IRoleRegistryAwarePolicyRegistry(registry).roleRegistry());
        if (actualRoleRegistry != expectedRoleRegistry) {
            revert PolicyRegistryRoleRegistryMismatch(registry, expectedRoleRegistry, actualRoleRegistry);
        }
        _policyRegistry = IPolicyRegistry(registry);
    }
}
