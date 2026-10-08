// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Minimal role-query interface for contracts using a shared registry.
/// @notice Consumers depend on this interface rather than the registry implementation.
/// @dev Membership management and administrator transfers are implementation APIs.
interface IRoleRegistry {
    /// @notice Returns the current global default administrator.
    function defaultAdmin() external view returns (address);

    /// @notice Checks effective membership for a target, including global membership.
    /// @dev Returns global membership OR membership for the requested target.
    /// A zero target queries global membership only. Local revocation does not
    /// remove access while the account still holds the same global role.
    /// @param target Contract whose access policy is being checked.
    /// @param role Required role identifier.
    /// @param account Account whose membership is queried.
    /// @return True if the account holds the role globally or for this target.
    function hasRoleFor(
        address target,
        bytes32 role,
        address account
    ) external view returns (bool);
}
