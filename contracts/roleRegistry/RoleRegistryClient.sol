// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {IRoleRegistry} from "./IRoleRegistry.sol";

/// @title Shared-registry access control for constructor-based contracts.
/// @notice Inherit this contract and protect functions with onlyRole(REQUIRED_ROLE).
/// @dev Example: constructor(address registry) RoleRegistryClient(registry) {}
/// Role membership is managed by the external registry, while the inheriting
/// contract decides which role each function requires. The registry address is
/// fixed at construction; role memberships remain managed by that registry.
abstract contract RoleRegistryClient is Context {
    bytes32 public constant DEFAULT_ADMIN_ROLE = bytes32(0);

    IRoleRegistry private _roleRegistry;

    /// @notice The registry has no deployed code or its default admin query is invalid or zero.
    error InvalidRoleRegistry(address registry);
    /// @notice The caller lacks the required global or target-specific role.
    error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);

    /// @param registry Deployed registry implementing IRoleRegistry, used for all membership checks.
    /// @dev Requires deployed code and a valid nonzero default admin. This does not
    /// prove full interface compatibility, role assignments, or trustworthiness.
    constructor(address registry) {
        if (registry.code.length == 0) revert InvalidRoleRegistry(registry);
        (bool success, bytes memory result) = registry.staticcall(
            abi.encodeCall(IRoleRegistry.defaultAdmin, ())
        );
        if (!success || result.length != 32) revert InvalidRoleRegistry(registry);
        uint256 admin = abi.decode(result, (uint256));
        if (admin == 0 || admin > type(uint160).max) revert InvalidRoleRegistry(registry);
        _roleRegistry = IRoleRegistry(registry);
    }

    /// @notice Requires the caller to hold role globally or for this contract.
    /// @dev Uses an explicit role, so it is also suitable for internal authorization hooks.
    modifier onlyRole(bytes32 role) {
        _checkRole(role, _msgSender());
        _;
    }

    /// @notice Returns the Registry currently used for membership checks.
    function roleRegistry() public view returns (IRoleRegistry) {
        return _roleRegistry;
    }

    /// @notice Checks effective membership for this contract.
    /// @param role Required role identifier.
    /// @param account Caller or another account, such as a recovered signature signer.
    /// @return True if account holds role globally or locally for address(this).
    function hasRole(bytes32 role, address account) public view virtual returns (bool) {
        return roleRegistry().hasRoleFor(address(this), role, account);
    }

    /// @dev Reverts when account lacks effective membership. Registry failures propagate.
    function _checkRole(bytes32 role, address account) internal view virtual {
        if (!hasRole(role, account)) {
            revert AccessControlUnauthorizedAccount(account, role);
        }
    }

    /// @dev Checks global default-admin membership for the consumer's admin operations.
    function _checkDefaultAdmin(address account) internal view {
        if (!roleRegistry().hasRoleFor(address(0), DEFAULT_ADMIN_ROLE, account)) {
            revert AccessControlUnauthorizedAccount(account, DEFAULT_ADMIN_ROLE);
        }
    }
}
