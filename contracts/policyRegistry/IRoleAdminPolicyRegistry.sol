// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IPolicyRegistry} from "./IPolicyRegistry.sol";

/// @title Global-role administration for the shared policy registry.
/// @dev Creation is permissionless. No role-member existence check is performed.
/// Admin roles are fixed at creation; no transfer, renunciation, or mode conversion is provided.
/// Membership, composite updates, and evaluation use the common IPolicyRegistry API and events.
interface IRoleAdminPolicyRegistry is IPolicyRegistry {
    /// @notice The operation requires the other admin model.
    error IncompatibleAdminType(uint64 policyId);

    event RolePolicyCreated(
        uint64 indexed policyId, address indexed creator, bytes32 indexed adminRole, PolicyType policyType
    );

    /// @notice Creates an empty simple policy administered by global holders of adminRole.
    /// @dev Any bytes32 is valid, including DEFAULT_ADMIN_ROLE (zero) and roles with no holders.
    function createRolePolicy(bytes32 adminRole, PolicyType policyType) external returns (uint64 newPolicyId);
    /// @notice Creates a simple role policy with at most 64 initial members.
    function createRolePolicyWithAccounts(bytes32 adminRole, PolicyType policyType, address[] calldata accounts)
        external returns (uint64 newPolicyId);
    /// @notice Creates a role-admin composite referencing 2-4 existing simple policies of either admin model.
    function createRoleCompositePolicy(bytes32 adminRole, PolicyType policyType, uint64[] calldata childPolicyIds)
        external returns (uint64 newPolicyId);

    /// @notice True only for existing role policies. Sentinels and unknown IDs return false.
    function isRolePolicy(uint64 policyId) external view returns (bool);
    /// @notice Returns the fixed role; zero is a valid DEFAULT_ADMIN_ROLE, not an absence marker.
    /// @dev Reverts PolicyNotFound for unknown IDs and IncompatibleAdminType for address policies/sentinels.
    function policyAdminRole(uint64 policyId) external view returns (bytes32);
}
