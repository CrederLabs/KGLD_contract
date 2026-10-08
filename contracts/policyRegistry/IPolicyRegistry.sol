// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title B20-style policy registry interface.
/// @dev API based on base/base-std src/interfaces/IPolicyRegistry.sol (main, reviewed 2026-09-17).
/// The Solidity implementation has no ActivationRegistry dependency. See PolicyRegistry NatSpec.
interface IPolicyRegistry {
    enum PolicyType { BLOCKLIST, ALLOWLIST, UNION, INTERSECT }

    /// @dev Included in the upstream ABI; Solidity's nonpayable dispatcher rejects ETH instead.
    error NonPayable();
    error Unauthorized();
    error PolicyNotFound();
    error IncompatiblePolicyType();
    error ZeroAddress();
    error BatchSizeTooLarge(uint256 maxBatchSize);
    error NoPendingAdmin();
    error ChildPoliciesOutsideOfRange();
    error InvalidChildPolicy(uint64 childPolicyId);

    event PolicyCreated(uint64 indexed policyId, address indexed creator, PolicyType policyType);
    event PolicyAdminStaged(uint64 indexed policyId, address indexed currentAdmin, address indexed pendingAdmin);
    event PolicyAdminUpdated(uint64 indexed policyId, address indexed previousAdmin, address indexed newAdmin);
    event AllowlistUpdated(uint64 indexed policyId, address indexed updater, bool allowed, address[] accounts);
    event BlocklistUpdated(uint64 indexed policyId, address indexed updater, bool blocked, address[] accounts);
    event CompositePolicyUpdated(uint64 indexed policyId, address indexed updater, uint64[] childPolicyIds);

    /// @notice Permissionless creation; only the nominated nonzero admin can subsequently mutate the policy.
    function createPolicy(address admin, PolicyType policyType) external returns (uint64 newPolicyId);
    /// @notice Creates a simple policy with at most 64 initial members.
    function createPolicyWithAccounts(address admin, PolicyType policyType, address[] calldata accounts)
        external returns (uint64 newPolicyId);
    /// @notice Creates a UNION or INTERSECT of 2-4 existing, non-sentinel simple policies.
    /// @dev Child policies may use either address or global-role administration.
    function createCompositePolicy(address admin, PolicyType policyType, uint64[] calldata childPolicyIds)
        external returns (uint64 newPolicyId);
    /// @notice Replaces the pending nominee; zero clears the nomination. No timelock is imposed.
    /// @dev Address-admin policies only.
    function stageUpdateAdmin(uint64 policyId, address newAdmin) external;
    /// @notice Only the current nominee may accept; clears the nomination on success.
    /// @dev Address-admin policies only.
    function finalizeUpdateAdmin(uint64 policyId) external;
    /// @notice Permanently removes administration and clears any pending nomination.
    /// @dev Address-admin policies only; a composite's children retain their own administrators.
    function renounceAdmin(uint64 policyId) external;
    /// @notice Updates membership; requires the stored address admin or a holder of the stored global admin role.
    function updateAllowlist(uint64 policyId, bool allowed, address[] calldata accounts) external;
    /// @notice Updates membership; requires the stored address admin or a holder of the stored global admin role.
    function updateBlocklist(uint64 policyId, bool blocked, address[] calldata accounts) external;
    /// @notice Replaces all children, preserving order and duplicates.
    /// @dev Checks the parent's admin only; children may use either admin model.
    function updateComposite(uint64 policyId, uint64[] calldata childPolicyIds) external;
    /// @notice Evaluates a policy; unknown BLOCKLIST IDs allow, unknown ALLOWLIST IDs deny.
    /// @dev Consumers MUST validate policyExists before storing an ID. Unknown composite/unsupported types deny here.
    function isAuthorized(uint64 policyId, address account) external view returns (bool);
    function MIN_COMPOSITE_CHILD_POLICIES() external view returns (uint256);
    function MAX_COMPOSITE_CHILD_POLICIES() external view returns (uint256);
    /// @notice Sentinels and assigned IDs exist, including renounced policies.
    function policyExists(uint64 policyId) external view returns (bool);
    /// @notice Returns zero for unknown IDs, sentinels, renounced policies, and role-admin policies.
    function policyAdmin(uint64 policyId) external view returns (address);
    /// @notice Returns zero when no nominee exists, including role-admin policies.
    function pendingPolicyAdmin(uint64 policyId) external view returns (address);
    /// @notice Returns an empty array for every ID that is not an existing composite.
    function compositePolicyChildIds(uint64 policyId) external view returns (uint64[] memory);
}
