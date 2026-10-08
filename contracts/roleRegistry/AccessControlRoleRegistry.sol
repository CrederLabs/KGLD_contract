// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {IRoleRegistry} from "./IRoleRegistry.sol";

/// @title Global and local role registry backed by OpenZeppelin AccessControl.
/// @notice hasRole() queries global membership; hasRoleFor() adds target-local membership.
/// @dev AccessControl owns global memberships and shared role-admin relationships.
/// Local memberships are independent and survive global revocation. Inherited
/// onlyRole checks remain global-only. Global changes emit OZ RoleGranted/RoleRevoked;
/// local changes emit LocalRoleGranted/LocalRoleRevoked. Deployment uses a standalone constructor
/// with a custom administrator-transfer policy. Times are in seconds.
contract AccessControlRoleRegistry is AccessControl, IRoleRegistry {
    /// @dev Explicit local membership; address(0) is never a valid local scope.
    mapping(address target => mapping(bytes32 role => mapping(address account => bool)))
        private _localRoles;

    /// @notice Emitted only when a target-local membership is added.
    event LocalRoleGranted(
        address indexed target,
        bytes32 indexed role,
        address indexed account,
        address sender
    );
    /// @notice Emitted only when a target-local membership is removed.
    event LocalRoleRevoked(
        address indexed target,
        bytes32 indexed role,
        address indexed account,
        address sender
    );

    /// @notice The latest administrator transfer reservation.
    /// @dev newAdmin == address(0) means no reservation. A finalized record is retained
    /// until a later reservation replaces it; expiration does not clear the record.
    struct PendingDefaultAdminUpdate {
        // Administrator at staging time; must still be current when accepted.
        address oldAdmin;
        // Nominee authorized to accept; zero indicates an empty reservation.
        address newAdmin;
        // Inclusive earliest acceptance timestamp.
        uint256 validAfter;
        // Exclusive acceptance deadline; expiration leaves the current admin unchanged.
        uint256 validBefore;
        // True after successful acceptance; prevents replay.
        bool finalized;
    }

    /// @notice Reserved scope for global membership; rejected by public local-role APIs.
    address public constant GLOBAL_TARGET = address(0);

    /// @notice The current administrator, updated atomically with its global membership.
    address private _defaultAdmin;

    /// @notice Length of the acceptance window after the transfer delay, fixed at deployment.
    uint256 public immutable defaultAdminAcceptanceWindow;
    /// @notice Latest transfer details; inspect newAdmin and finalized before treating it as pending.
    PendingDefaultAdminUpdate public pendingDefaultAdminUpdate;

    /// @dev Stored base delay; use defaultAdminUpdateTimelock() to include a matured decrease.
    uint256 private _defaultAdminUpdateTimelock;
    /// @notice Scheduled replacement delay, which may be zero.
    /// @dev This value alone does not indicate whether a change exists.
    uint256 public pendingDefaultAdminUpdateTimelock;
    /// @notice Timestamp when the replacement delay takes effect; zero means no scheduled change.
    /// @dev A matured schedule remains stored until the next delay-setting call.
    uint256 public pendingDefaultAdminUpdateTimelockValidAfter;

    /// @notice Emitted with the fixed acceptance interval [validAfter, validBefore).
    event DefaultAdminUpdateStaged(
        address indexed oldAdmin,
        address indexed newAdmin,
        uint256 validAfter,
        uint256 validBefore
    );
    /// @notice Emitted after the old administrator is replaced by the accepting nominee.
    event DefaultAdminUpdateFinalized(
        address indexed oldAdmin,
        address indexed newAdmin
    );
    /// @notice Emitted when the current administrator clears an unfinalized reservation.
    event DefaultAdminUpdateCanceled(address indexed newAdmin);
    /// @notice Emitted for both delayed decreases and immediate updates.
    /// @dev For immediate updates, validAfter is the current block timestamp.
    event DefaultAdminUpdateTimelockScheduled(
        uint256 timelock,
        uint256 validAfter
    );

    /// @notice Ordinary grants cannot assign DEFAULT_ADMIN_ROLE.
    error DefaultAdminGrantForbidden();
    /// @notice Ordinary revocations cannot remove DEFAULT_ADMIN_ROLE.
    error DefaultAdminRevokeForbidden();
    /// @notice The default administrator cannot renounce its role.
    error DefaultAdminRenounceForbidden();
    /// @notice A local-role API was called with the reserved global target.
    error GlobalTargetForbidden();
    /// @notice The admin role of DEFAULT_ADMIN_ROLE cannot be changed.
    error DefaultAdminRoleAdminChangeForbidden();
    /// @notice An administrator address or its storage scope is invalid.
    error InvalidDefaultAdmin(address account);
    /// @notice The acceptance window must be greater than zero.
    error InvalidAcceptanceWindow();
    /// @notice An unexpired, unfinalized reservation blocks staging another.
    error DefaultAdminUpdateAlreadyPending();
    /// @notice There is no reservation, or it was already finalized.
    error NoPendingDefaultAdminUpdate();
    /// @notice The acceptance delay has not elapsed.
    error DefaultAdminUpdateNotReady();
    /// @notice The exclusive acceptance deadline has been reached.
    error DefaultAdminUpdateExpired();
    /// @notice The reservation does not match the current admin or the supplied nominee.
    error DefaultAdminUpdateMismatch();

    /// @notice Creates the registry with exactly one nonzero global administrator.
    /// @param initialAdmin Account receiving DEFAULT_ADMIN_ROLE immediately.
    /// @param initialTimelock Initial transfer delay in seconds; zero is allowed.
    /// @param acceptanceWindow Nonzero duration in seconds available to accept a transfer.
    constructor(
        address initialAdmin,
        uint256 initialTimelock,
        uint256 acceptanceWindow
    ) {
        if (initialAdmin == address(0))
            revert InvalidDefaultAdmin(initialAdmin);
        if (acceptanceWindow == 0) revert InvalidAcceptanceWindow();
        _defaultAdminUpdateTimelock = initialTimelock;
        defaultAdminAcceptanceWindow = acceptanceWindow;
        _updateDefaultAdmin(initialAdmin);
    }

    /// @notice Restricts configuration and transfer staging/cancellation to the current administrator.
    modifier onlyDefaultAdmin() {
        _checkRole(DEFAULT_ADMIN_ROLE);
        _;
    }

    /// @inheritdoc IRoleRegistry
    function hasRoleFor(
        address target,
        bytes32 role,
        address account
    ) public view override returns (bool) {
        return hasRole(role, account) || _localRoles[target][role][account];
    }

    /// @notice Alias for AccessControl.hasRole(), querying global membership only.
    function hasGlobalRole(
        bytes32 role,
        address account
    ) external view returns (bool) {
        return hasRole(role, account);
    }

    /// @notice Returns explicit local membership, without global fallback.
    /// @param target Nonzero address defining the local scope.
    /// @param role Role to query.
    /// @param account Account whose local membership is queried.
    function hasLocalRole(
        address target,
        bytes32 role,
        address account
    ) external view returns (bool) {
        _checkLocalTarget(target);
        return _localRoles[target][role][account];
    }

    /// @notice Advertises the registry query interface in addition to OZ interfaces.
    function supportsInterface(
        bytes4 interfaceId
    ) public view override returns (bool) {
        return
            interfaceId == type(IRoleRegistry).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    /// @notice Grants a global role using the inherited role-admin authorization.
    /// @dev Default-admin membership may change only through the transfer workflow.
    function grantRole(bytes32 role, address account) public override {
        if (role == DEFAULT_ADMIN_ROLE) revert DefaultAdminGrantForbidden();
        super.grantRole(role, account);
    }

    /// @notice Revokes a global role; local memberships are unaffected.
    /// @dev Uses OZ authorization and blocks direct default-admin revocation.
    function revokeRole(bytes32 role, address account) public override {
        if (role == DEFAULT_ADMIN_ROLE) revert DefaultAdminRevokeForbidden();
        super.revokeRole(role, account);
    }

    /// @notice Renounces the caller's global role using OZ caller confirmation.
    /// @dev Local memberships survive; DEFAULT_ADMIN_ROLE cannot be renounced.
    function renounceRole(
        bytes32 role,
        address callerConfirmation
    ) public override {
        if (role == DEFAULT_ADMIN_ROLE) revert DefaultAdminRenounceForbidden();
        super.renounceRole(role, callerConfirmation);
    }

    /// @notice Alias for grantRole(); caller must hold getRoleAdmin(role) globally.
    function grantGlobalRole(bytes32 role, address account) external {
        grantRole(role, account);
    }

    /// @notice Alias for revokeRole(); caller must hold getRoleAdmin(role) globally.
    function revokeGlobalRole(bytes32 role, address account) external {
        revokeRole(role, account);
    }

    /// @notice Renounces only the caller's global membership, without a separate confirmation argument.
    function renounceGlobalRole(bytes32 role) external {
        renounceRole(role, _msgSender());
    }

    /// @notice Grants a role for one target, independently of any global membership.
    /// @dev Requires the role's admin globally or locally for this target.
    /// @param role Role to grant; DEFAULT_ADMIN_ROLE is forbidden.
    /// @param target Nonzero address defining the local scope.
    /// @param account Account receiving local membership.
    function grantLocalRole(
        bytes32 role,
        address target,
        address account
    ) external {
        if (role == DEFAULT_ADMIN_ROLE) revert DefaultAdminGrantForbidden();
        _checkLocalTarget(target);
        _checkRoleFor(target, getRoleAdmin(role));
        _grantLocalRole(target, role, account);
    }

    /// @notice Removes local membership; global membership still grants access.
    /// @dev Requires the role's admin globally or locally for this target.
    /// @param role Role to revoke; DEFAULT_ADMIN_ROLE is forbidden.
    /// @param target Nonzero address defining the local scope.
    /// @param account Account losing local membership.
    function revokeLocalRole(
        bytes32 role,
        address target,
        address account
    ) external {
        if (role == DEFAULT_ADMIN_ROLE) revert DefaultAdminRevokeForbidden();
        _checkLocalTarget(target);
        _checkRoleFor(target, getRoleAdmin(role));
        _revokeLocalRole(target, role, account);
    }

    /// @notice Removes only the caller's local membership; no admin permission is required.
    /// @param role Role to relinquish; DEFAULT_ADMIN_ROLE is forbidden.
    /// @param target Nonzero address defining the local scope.
    function renounceLocalRole(bytes32 role, address target) external {
        if (role == DEFAULT_ADMIN_ROLE) revert DefaultAdminRenounceForbidden();
        _revokeLocalRole(target, role, _msgSender());
    }

    /// @notice Sets the role admin shared by global and every local scope.
    /// @dev Only the default administrator may configure this mapping. Existing
    /// memberships remain unchanged; the default admin's own admin cannot change.
    function setRoleAdmin(
        bytes32 role,
        bytes32 adminRole
    ) external onlyDefaultAdmin {
        _setRoleAdmin(role, adminRole);
    }

    /// @dev Enforces the locked default-admin relationship on internal paths as well.
    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal override {
        if (role == DEFAULT_ADMIN_ROLE)
            revert DefaultAdminRoleAdminChangeForbidden();
        super._setRoleAdmin(role, adminRole);
    }

    /// @dev Authorizes a local operation without changing OZ's global-only _checkRole.
    function _checkRoleFor(address target, bytes32 role) internal view {
        if (!hasRoleFor(target, role, _msgSender())) {
            revert AccessControlUnauthorizedAccount(_msgSender(), role);
        }
    }

    /// @dev Prevents local APIs from treating the global sentinel as a target.
    function _checkLocalTarget(address target) internal pure {
        if (target == GLOBAL_TARGET) revert GlobalTargetForbidden();
    }

    /// @dev No caller authorization: entry points must check it before calling.
    /// Exact local membership is checked so global holders can receive local grants.
    function _grantLocalRole(
        address target,
        bytes32 role,
        address account
    ) internal {
        _checkLocalTarget(target);
        if (role == DEFAULT_ADMIN_ROLE) revert DefaultAdminGrantForbidden();
        if (!_localRoles[target][role][account]) {
            _localRoles[target][role][account] = true;
            emit LocalRoleGranted(target, role, account, _msgSender());
        }
    }

    /// @dev No caller authorization. Only exact local membership is removed.
    function _revokeLocalRole(
        address target,
        bytes32 role,
        address account
    ) internal {
        _checkLocalTarget(target);
        if (role == DEFAULT_ADMIN_ROLE) revert DefaultAdminRevokeForbidden();
        if (_localRoles[target][role][account]) {
            _localRoles[target][role][account] = false;
            emit LocalRoleRevoked(target, role, account, _msgSender());
        }
    }

    /// @notice Returns the administrator whose global membership is maintained by this registry.
    /// @dev Preserves the original getter ABI while preventing direct assignment by children.
    function defaultAdmin() public view returns (address) {
        return _defaultAdmin;
    }

    /// @dev Ordinary internal grants cannot change the default administrator.
    /// Non-virtual to prevent derived contracts from overriding this guard.
    function _grantRole(
        bytes32 role,
        address account
    ) internal override returns (bool) {
        if (role == DEFAULT_ADMIN_ROLE) revert DefaultAdminGrantForbidden();
        return super._grantRole(role, account);
    }

    /// @dev Ordinary internal revocations cannot remove default-admin membership.
    /// Non-virtual to prevent derived contracts from overriding this guard.
    function _revokeRole(
        bytes32 role,
        address account
    ) internal override returns (bool) {
        if (role == DEFAULT_ADMIN_ROLE) revert DefaultAdminRevokeForbidden();
        return super._revokeRole(role, account);
    }

    /// @dev Sole registry path for updating the administrator and its membership.
    /// Called only by construction and validated transfer finalization. Explicit
    /// parent calls bypass the ordinary guards while retaining OZ storage and events.
    /// There are no external calls during this transition; any failure reverts it all.
    /// This protects normal extension paths, not arbitrary assembly or deliberate
    /// ancestor-qualified AccessControl calls in a derived implementation.
    function _updateDefaultAdmin(address newAdmin) private {
        if (newAdmin == address(0)) revert InvalidDefaultAdmin(newAdmin);
        address oldAdmin = _defaultAdmin;
        if (oldAdmin != address(0)) {
            super._revokeRole(DEFAULT_ADMIN_ROLE, oldAdmin);
        }
        _defaultAdmin = newAdmin;
        super._grantRole(DEFAULT_ADMIN_ROLE, newAdmin);
    }

    /// @notice Returns the effective delay, including a matured scheduled decrease.
    /// @dev Maturation requires no transaction. Reading does not clear the schedule
    /// or update the stored base delay. Existing transfer reservations are unaffected.
    /// @return Current delay in seconds for newly staged administrator transfers.
    function defaultAdminUpdateTimelock() public view returns (uint256) {
        uint256 effectiveAt = pendingDefaultAdminUpdateTimelockValidAfter;
        if (effectiveAt != 0 && block.timestamp >= effectiveAt) {
            return pendingDefaultAdminUpdateTimelock;
        }
        return _defaultAdminUpdateTimelock;
    }

    /// @notice Updates the transfer delay; decreases wait out the current effective delay.
    /// @dev Only the default administrator may call this. Increases and equal values
    /// apply immediately and clear a prior schedule. A decrease replaces any earlier
    /// schedule and starts a fresh waiting period using the current effective delay.
    /// Already staged transfer deadlines never change.
    /// @param timelock New delay in seconds; zero is allowed.
    function setDefaultAdminUpdateTimelock(
        uint256 timelock
    ) external onlyDefaultAdmin {
        uint256 currentTimelock = defaultAdminUpdateTimelock();
        // Materialize any matured decrease before replacing its schedule.
        _defaultAdminUpdateTimelock = currentTimelock;
        if (timelock < currentTimelock) {
            pendingDefaultAdminUpdateTimelock = timelock;
            pendingDefaultAdminUpdateTimelockValidAfter =
                block.timestamp +
                currentTimelock;
            emit DefaultAdminUpdateTimelockScheduled(
                timelock,
                pendingDefaultAdminUpdateTimelockValidAfter
            );
        } else {
            _defaultAdminUpdateTimelock = timelock;
            delete pendingDefaultAdminUpdateTimelock;
            delete pendingDefaultAdminUpdateTimelockValidAfter;
            emit DefaultAdminUpdateTimelockScheduled(timelock, block.timestamp);
        }
    }

    /// @notice Reserves a transfer for the nominee to accept after the effective delay.
    /// @dev Only the current administrator may stage. Unexpired, unfinalized
    /// reservations must first be canceled. Expired or finalized records may be
    /// replaced directly, with a fresh delay and acceptance window. Staging does
    /// not grant any role or remove the current administrator.
    /// @param newAdmin Nonzero nominee different from the current administrator.
    function stageUpdateDefaultAdmin(
        address newAdmin
    ) external onlyDefaultAdmin {
        if (newAdmin == address(0) || newAdmin == _defaultAdmin)
            revert InvalidDefaultAdmin(newAdmin);
        PendingDefaultAdminUpdate storage pending = pendingDefaultAdminUpdate;
        if (
            pending.newAdmin != address(0) &&
            !pending.finalized &&
            block.timestamp < pending.validBefore
        ) revert DefaultAdminUpdateAlreadyPending();
        // Snapshot both deadlines so later delay changes cannot alter this transfer.
        uint256 validAfter = block.timestamp + defaultAdminUpdateTimelock();
        uint256 validBefore = validAfter + defaultAdminAcceptanceWindow;
        pendingDefaultAdminUpdate = PendingDefaultAdminUpdate(
            _defaultAdmin,
            newAdmin,
            validAfter,
            validBefore,
            false
        );
        emit DefaultAdminUpdateStaged(
            _defaultAdmin,
            newAdmin,
            validAfter,
            validBefore
        );
    }

    /// @notice Accepts a staged transfer and atomically replaces the default administrator.
    /// @dev Only the nominated account may accept, with validAfter <= timestamp <
    /// validBefore. A repeated acceptance reverts. Other role memberships held by
    /// either account remain unchanged. The finalized reservation is retained.
    /// @param callerConfirmation Must equal _msgSender(), which must be the nominee.
    function finalizeDefaultAdmin(address callerConfirmation) external {
        PendingDefaultAdminUpdate storage pending = pendingDefaultAdminUpdate;
        if (pending.newAdmin == address(0) || pending.finalized)
            revert NoPendingDefaultAdminUpdate();
        if (
            _msgSender() != pending.newAdmin ||
            callerConfirmation != _msgSender()
        ) revert AccessControlBadConfirmation();
        if (pending.oldAdmin != _defaultAdmin)
            revert DefaultAdminUpdateMismatch();
        if (block.timestamp < pending.validAfter)
            revert DefaultAdminUpdateNotReady();
        if (block.timestamp >= pending.validBefore)
            revert DefaultAdminUpdateExpired();

        address oldAdmin = pending.oldAdmin;
        address newAdmin = pending.newAdmin;
        // No external calls occur during this transition; a revert rolls it all back.
        pending.finalized = true;
        _updateDefaultAdmin(newAdmin);
        emit DefaultAdminUpdateFinalized(oldAdmin, newAdmin);
    }

    /// @notice Clears an unfinalized reservation without changing the current administrator.
    /// @dev Only the current administrator may cancel, before or after expiration.
    /// A finalized reservation cannot be canceled.
    /// @param newAdmin Must match the stored nominee to identify the reservation.
    function cancelUpdateDefaultAdmin(
        address newAdmin
    ) external onlyDefaultAdmin {
        PendingDefaultAdminUpdate storage pending = pendingDefaultAdminUpdate;
        if (pending.newAdmin == address(0) || pending.finalized)
            revert NoPendingDefaultAdminUpdate();
        if (newAdmin != pending.newAdmin) revert DefaultAdminUpdateMismatch();
        delete pendingDefaultAdminUpdate;
        emit DefaultAdminUpdateCanceled(newAdmin);
    }
}
