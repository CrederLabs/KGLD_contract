// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ContextUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import {IRoleRegistry} from "./IRoleRegistry.sol";

/// @title Shared-registry access control for proxy-based contracts.
/// @notice Call __RoleRegistryClient_init(registry) from the child's initializer,
/// then protect functions with onlyRole(REQUIRED_ROLE).
/// @dev Initialize the proxy atomically at deployment and disable initializers in
/// the concrete implementation's constructor. This module provides access control,
/// not an upgrade mechanism. The registry is set once; replacement requires a new
/// implementation with an explicit migration. The registry itself is standalone.
abstract contract RoleRegistryClientUpgradeable is Initializable, ContextUpgradeable {
    bytes32 public constant DEFAULT_ADMIN_ROLE = bytes32(0);

    // Preserve the original namespace and slot across the source-level rename.
    /// @custom:storage-location erc7201:kgold.storage.RoleRegistryAccess
    struct RoleRegistryClientStorage {
        IRoleRegistry registry;
    }

    // keccak256(abi.encode(uint256(keccak256("kgold.storage.RoleRegistryAccess")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ROLE_REGISTRY_CLIENT_STORAGE_LOCATION =
        0x1b79fc0855788337bb31001f993ff83070c6001b415d3376252358a993bb2400;

    /// @notice Registry initialization is missing, code is absent, or its default admin query is invalid or zero.
    error InvalidRoleRegistry(address registry);
    /// @notice Registry initialization was attempted more than once, including via reinitializers.
    error RoleRegistryAlreadyInitialized();
    /// @notice The caller lacks the required global or target-specific role.
    error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);

    /// @notice Records registry installation during a consumer's migration.
    event RoleRegistryUpdated(address indexed previousRegistry, address indexed newRegistry);

    /// @dev Initializes the context and registry during the child's initialization.
    /// @param registry Deployed registry implementing IRoleRegistry, shared by the managed contracts.
    function __RoleRegistryClient_init(address registry) internal onlyInitializing {
        __Context_init();
        __RoleRegistryClient_init_unchained(registry);
    }

    /// @dev Initializes only this module. The nonzero storage guard prevents later
    /// reinitializers from replacing the registry through this initialization path.
    /// Requires deployed code and a valid nonzero default admin; role assignments
    /// and full interface compatibility must be verified before deployment.
    function __RoleRegistryClient_init_unchained(address registry) internal onlyInitializing {
        RoleRegistryClientStorage storage $ = _getRoleRegistryClientStorage();
        if (address($.registry) != address(0)) revert RoleRegistryAlreadyInitialized();
        if (registry.code.length == 0) revert InvalidRoleRegistry(registry);
        (bool success, bytes memory result) = registry.staticcall(
            abi.encodeCall(IRoleRegistry.defaultAdmin, ())
        );
        if (!success || result.length != 32) revert InvalidRoleRegistry(registry);
        uint256 admin = abi.decode(result, (uint256));
        if (admin == 0 || admin > type(uint160).max) revert InvalidRoleRegistry(registry);
        $.registry = IRoleRegistry(registry);
    }

    /// @notice Requires the caller to hold role globally or for this proxy.
    /// @dev Uses an explicit role rather than the external entry point's selector.
    modifier onlyRole(bytes32 role) {
        _checkRole(role, _msgSender());
        _;
    }

    /// @notice Returns the Registry currently used for membership checks; zero before initialization.
    function roleRegistry() public view returns (IRoleRegistry) {
        return _getRoleRegistryClientStorage().registry;
    }

    /// @notice Checks effective membership for the proxy executing this code.
    /// @param role Required role identifier.
    /// @param account Caller or another account, such as a recovered signature signer.
    /// @return True for global membership or local membership at the proxy address.
    function hasRole(bytes32 role, address account) public view virtual returns (bool) {
        IRoleRegistry registry = roleRegistry();
        if (address(registry) == address(0)) revert InvalidRoleRegistry(address(0));
        return registry.hasRoleFor(address(this), role, account);
    }

    /// @dev Reverts when account lacks effective membership. Registry failures propagate.
    function _checkRole(bytes32 role, address account) internal view virtual {
        if (!hasRole(role, account)) {
            revert AccessControlUnauthorizedAccount(account, role);
        }
    }

    /// @dev Checks global default-admin membership for the consumer's admin operations.
    function _checkDefaultAdmin(address account) internal view {
        IRoleRegistry registry = roleRegistry();
        if (
            address(registry) == address(0) ||
            !registry.hasRoleFor(address(0), DEFAULT_ADMIN_ROLE, account)
        ) {
            revert AccessControlUnauthorizedAccount(account, DEFAULT_ADMIN_ROLE);
        }
    }

    /// @dev Isolates this module's storage from ordinary child-contract storage slots.
    function _getRoleRegistryClientStorage() private pure returns (RoleRegistryClientStorage storage $) {
        assembly {
            $.slot := ROLE_REGISTRY_CLIENT_STORAGE_LOCATION
        }
    }
}
