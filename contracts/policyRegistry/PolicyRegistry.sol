// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IPolicyRegistry} from "./IPolicyRegistry.sol";
import {IRoleAdminPolicyRegistry} from "./IRoleAdminPolicyRegistry.sol";
import {IRoleRegistryAwarePolicyRegistry} from "./IRoleRegistryAwarePolicyRegistry.sol";
import {IRoleRegistry} from "../roleRegistry/IRoleRegistry.sol";
import {RoleRegistryClient} from "../roleRegistry/RoleRegistryClient.sol";

/// @title Shared B20-style allowlists, blocklists, and composite policies.
/// @notice Deploy directly: this contract has no proxy initializer or upgrade mechanism.
/// Policies share storage and evaluation; only administration differs by address or global role.
/// Composites may combine children administered by either model.
/// @dev Solidity adaptation of base-std/main's policy API, not a native Base precompile.
/// No ActivationRegistry gate is used. Solidity rejects ETH and invalid enum ABI values
/// in its dispatcher; exact precompile revert payloads/validation order are not promised.
/// Unknown BLOCKLIST IDs authorize; unknown ALLOWLIST/composite/unsupported IDs deny.
/// Always validate policyExists when binding a policy to a consumer.
contract PolicyRegistry is IRoleAdminPolicyRegistry, IRoleRegistryAwarePolicyRegistry, RoleRegistryClient {
    uint64 public constant ALWAYS_ALLOW = 0;
    uint64 public constant ALWAYS_BLOCK =
        (uint64(PolicyType.ALLOWLIST) << 56) | 1;
    uint256 public constant MAX_BATCH_SIZE = 64;
    uint256 public constant override MIN_COMPOSITE_CHILD_POLICIES = 2;
    uint256 public constant override MAX_COMPOSITE_CHILD_POLICIES = 4;

    struct Policy {
        address admin;
        bool exists;
        bool roleBased;
        address pendingAdmin;
        mapping(address => bool) members;
        uint64[] children;
        bytes32 adminRole;
    }

    // Global allocation across all policy types and admin models.
    uint56 private _nextPolicyCounter = 2;
    mapping(uint64 => Policy) private _policies;

    /// @param registry RoleRegistry fixed at deployment and used for global role checks.
    constructor(address registry) RoleRegistryClient(registry) {}

    /// @inheritdoc IRoleRegistryAwarePolicyRegistry
    function roleRegistry()
        public view override(RoleRegistryClient, IRoleRegistryAwarePolicyRegistry) returns (IRoleRegistry)
    {
        return super.roleRegistry();
    }

    /// @inheritdoc IPolicyRegistry
    function createPolicy(
        address admin,
        PolicyType policyType
    ) external override returns (uint64) {
        _validateSimple(admin, policyType);
        return _create(admin, bytes32(0), policyType);
    }

    /// @inheritdoc IPolicyRegistry
    function createPolicyWithAccounts(
        address admin,
        PolicyType policyType,
        address[] calldata accounts
    ) external override returns (uint64 policyId) {
        _validateSimple(admin, policyType);
        _checkBatch(accounts.length);
        policyId = _create(admin, bytes32(0), policyType);
        _setMembers(policyId, policyType, true, accounts);
    }

    /// @inheritdoc IPolicyRegistry
    function createCompositePolicy(
        address admin,
        PolicyType policyType,
        uint64[] calldata childPolicyIds
    ) external override returns (uint64 policyId) {
        if (admin == address(0)) revert ZeroAddress();
        _validateCompositeType(uint8(policyType));
        _validateChildren(childPolicyIds);
        policyId = _create(admin, bytes32(0), policyType);
        _setChildren(policyId, childPolicyIds);
    }

    /// @inheritdoc IPolicyRegistry
    function stageUpdateAdmin(
        uint64 policyId,
        address newAdmin
    ) external override {
        _requireAdminType(policyId, false);
        Policy storage policy = _policies[policyId];
        _checkPolicyAdmin(policyId);
        policy.pendingAdmin = newAdmin;
        emit PolicyAdminStaged(policyId, policy.admin, newAdmin);
    }

    /// @inheritdoc IPolicyRegistry
    function finalizeUpdateAdmin(uint64 policyId) external override {
        _requireAdminType(policyId, false);
        Policy storage policy = _policies[policyId];
        address nominee = policy.pendingAdmin;
        if (nominee == address(0)) revert NoPendingAdmin();
        if (msg.sender != nominee) revert Unauthorized();
        address previous = policy.admin;
        policy.admin = nominee;
        delete policy.pendingAdmin;
        emit PolicyAdminUpdated(policyId, previous, nominee);
    }

    /// @inheritdoc IPolicyRegistry
    /// @dev For composites, only the child references freeze; child admins can still
    /// change their own member sets, so the composite's authorization result can change.
    function renounceAdmin(uint64 policyId) external override {
        _requireAdminType(policyId, false);
        Policy storage policy = _policies[policyId];
        _checkPolicyAdmin(policyId);
        address previous = policy.admin;
        delete policy.admin;
        delete policy.pendingAdmin;
        emit PolicyAdminUpdated(policyId, previous, address(0));
    }

    /// @inheritdoc IPolicyRegistry
    function updateAllowlist(
        uint64 policyId,
        bool allowed,
        address[] calldata accounts
    ) external override {
        _updateMembers(policyId, PolicyType.ALLOWLIST, allowed, accounts);
    }

    /// @inheritdoc IPolicyRegistry
    function updateBlocklist(
        uint64 policyId,
        bool blocked,
        address[] calldata accounts
    ) external override {
        _updateMembers(policyId, PolicyType.BLOCKLIST, blocked, accounts);
    }

    /// @inheritdoc IPolicyRegistry
    function updateComposite(
        uint64 policyId,
        uint64[] calldata childPolicyIds
    ) external override {
        _requireExists(policyId);
        _validateCompositeType(_policyType(policyId));
        _checkPolicyAdmin(policyId);
        _validateChildren(childPolicyIds);
        _setChildren(policyId, childPolicyIds);
    }

    /// @inheritdoc IRoleAdminPolicyRegistry
    function createRolePolicy(
        bytes32 adminRole,
        PolicyType policyType
    ) external override returns (uint64) {
        _validateSimpleType(policyType);
        return _create(address(0), adminRole, policyType);
    }

    /// @inheritdoc IRoleAdminPolicyRegistry
    function createRolePolicyWithAccounts(
        bytes32 adminRole,
        PolicyType policyType,
        address[] calldata accounts
    ) external override returns (uint64 policyId) {
        _validateSimpleType(policyType);
        _checkBatch(accounts.length);
        policyId = _create(address(0), adminRole, policyType);
        _setMembers(policyId, policyType, true, accounts);
    }

    /// @inheritdoc IRoleAdminPolicyRegistry
    function createRoleCompositePolicy(
        bytes32 adminRole,
        PolicyType policyType,
        uint64[] calldata childPolicyIds
    ) external override returns (uint64 policyId) {
        _validateCompositeType(uint8(policyType));
        _validateChildren(childPolicyIds);
        policyId = _create(address(0), adminRole, policyType);
        _setChildren(policyId, childPolicyIds);
    }

    /// @inheritdoc IRoleAdminPolicyRegistry
    function isRolePolicy(
        uint64 policyId
    ) external view override returns (bool) {
        return _policies[policyId].roleBased;
    }

    /// @inheritdoc IRoleAdminPolicyRegistry
    function policyAdminRole(
        uint64 policyId
    ) external view override returns (bytes32) {
        _requireAdminType(policyId, true);
        return _policies[policyId].adminRole;
    }

    /// @inheritdoc IPolicyRegistry
    function isAuthorized(
        uint64 policyId,
        address account
    ) external view override returns (bool) {
        uint8 kind = _policyType(policyId);
        if (kind <= uint8(PolicyType.ALLOWLIST))
            return _simpleAuthorized(policyId, account);
        // No enum cast on arbitrary IDs: malformed inputs must not cause an enum panic.
        if (!policyExists(policyId) || kind > uint8(PolicyType.INTERSECT))
            return false;
        uint64[] storage children = _policies[policyId].children;
        bool isUnion = kind == uint8(PolicyType.UNION);
        for (uint256 i; i < children.length; ++i) {
            bool authorized = _simpleAuthorized(children[i], account);
            if (isUnion && authorized) return true;
            if (!isUnion && !authorized) return false;
        }
        return !isUnion;
    }

    /// @inheritdoc IPolicyRegistry
    function policyExists(uint64 policyId) public view override returns (bool) {
        return
            policyId == ALWAYS_ALLOW ||
            policyId == ALWAYS_BLOCK ||
            _policies[policyId].exists;
    }

    /// @inheritdoc IPolicyRegistry
    function policyAdmin(
        uint64 policyId
    ) external view override returns (address) {
        return _policies[policyId].admin;
    }

    /// @inheritdoc IPolicyRegistry
    function pendingPolicyAdmin(
        uint64 policyId
    ) external view override returns (address) {
        return _policies[policyId].pendingAdmin;
    }

    /// @inheritdoc IPolicyRegistry
    function compositePolicyChildIds(
        uint64 policyId
    ) external view override returns (uint64[] memory) {
        return _policies[policyId].children;
    }

    function _validateSimple(
        address admin,
        PolicyType policyType
    ) private pure {
        if (admin == address(0)) revert ZeroAddress();
        _validateSimpleType(policyType);
    }

    function _validateSimpleType(PolicyType policyType) private pure {
        if (
            policyType != PolicyType.BLOCKLIST &&
            policyType != PolicyType.ALLOWLIST
        ) {
            revert IncompatiblePolicyType();
        }
    }

    function _validateCompositeType(uint8 kind) private pure {
        if (
            kind != uint8(PolicyType.UNION) &&
            kind != uint8(PolicyType.INTERSECT)
        ) {
            revert IncompatiblePolicyType();
        }
    }

    /// @dev Address creation validates nonzero admin first; only role creation passes zero here.
    function _create(
        address admin,
        bytes32 adminRole,
        PolicyType policyType
    ) private returns (uint64 policyId) {
        uint56 counter = _nextPolicyCounter;
        _nextPolicyCounter = counter + 1; // Panic(0x11) on exhaustion, before any assignment/events.
        policyId = (uint64(policyType) << 56) | uint64(counter);
        Policy storage policy = _policies[policyId];
        policy.exists = true;
        // If the admin is the zero address, this is a role-based policy.
        if (admin == address(0)) {
            policy.roleBased = true;
            policy.adminRole = adminRole;
            emit RolePolicyCreated(policyId, msg.sender, adminRole, policyType);
        }
        // If the admin is not the zero address, this is a simple policy with a direct admin.
        else {
            policy.admin = admin;
            emit PolicyCreated(policyId, msg.sender, policyType);
            emit PolicyAdminUpdated(policyId, address(0), admin);
        }
    }

    function _updateMembers(
        uint64 policyId,
        PolicyType policyType,
        bool member,
        address[] calldata accounts
    ) private {
        _requireExists(policyId);
        if (_policyType(policyId) != uint8(policyType))
            revert IncompatiblePolicyType();
        _checkPolicyAdmin(policyId);
        _checkBatch(accounts.length);
        _setMembers(policyId, policyType, member, accounts);
    }

    /// @dev Empty batches, duplicates, and address(0) are valid members; emit the submitted batch verbatim.
    function _setMembers(
        uint64 policyId,
        PolicyType policyType,
        bool member,
        address[] calldata accounts
    ) private {
        mapping(address => bool) storage members = _policies[policyId].members;
        for (uint256 i; i < accounts.length; ++i) {
            members[accounts[i]] = member;
        }
        if (policyType == PolicyType.ALLOWLIST)
            emit AllowlistUpdated(policyId, msg.sender, member, accounts);
        else emit BlocklistUpdated(policyId, msg.sender, member, accounts);
    }

    function _setChildren(
        uint64 policyId,
        uint64[] calldata childPolicyIds
    ) private {
        _policies[policyId].children = childPolicyIds;
        emit CompositePolicyUpdated(policyId, msg.sender, childPolicyIds);
    }

    function _validateChildren(uint64[] calldata childPolicyIds) private view {
        if (
            childPolicyIds.length < MIN_COMPOSITE_CHILD_POLICIES ||
            childPolicyIds.length > MAX_COMPOSITE_CHILD_POLICIES
        ) {
            revert ChildPoliciesOutsideOfRange();
        }
        for (uint256 i; i < childPolicyIds.length; ++i) {
            uint64 child = childPolicyIds[i];
            _requireExists(child);
            if (
                child == ALWAYS_ALLOW ||
                child == ALWAYS_BLOCK ||
                _policyType(child) > uint8(PolicyType.ALLOWLIST)
            ) {
                revert InvalidChildPolicy(child);
            }
        }
    }

    /// @dev Do not use inherited onlyRole: it also accepts target-local roles.
    function _checkPolicyAdmin(uint64 policyId) private view {
        Policy storage policy = _policies[policyId];
        if (policy.roleBased) {
            bytes32 adminRole = policy.adminRole;
            if (
                !roleRegistry().hasRoleFor(address(0), adminRole, _msgSender())
            ) {
                revert AccessControlUnauthorizedAccount(
                    _msgSender(),
                    adminRole
                );
            }
        } else {
            address admin = policy.admin;
            // Zero-sender eth_call must not mutate frozen/sentinel state.
            if (admin == address(0) || msg.sender != admin)
                revert Unauthorized();
        }
    }

    function _requireExists(uint64 policyId) private view {
        if (!policyExists(policyId)) revert PolicyNotFound();
    }

    function _requireAdminType(uint64 policyId, bool roleBased) private view {
        _requireExists(policyId);
        if (_policies[policyId].roleBased != roleBased)
            revert IncompatibleAdminType(policyId);
    }

    function _checkBatch(uint256 length) private pure {
        if (length > MAX_BATCH_SIZE) revert BatchSizeTooLarge(MAX_BATCH_SIZE);
    }

    function _simpleAuthorized(
        uint64 policyId,
        address account
    ) private view returns (bool) {
        bool member = _policies[policyId].members[account];
        return
            _policyType(policyId) == uint8(PolicyType.BLOCKLIST)
                ? !member
                : member;
    }

    function _policyType(uint64 policyId) private pure returns (uint8) {
        return uint8(policyId >> 56);
    }
}
