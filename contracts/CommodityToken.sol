// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC7943Fungible} from "./IERC7943Fungible.sol";
import {ITreasury} from "./controller/ITreasury.sol";
import {IPolicyRegistry} from "./policyRegistry/IPolicyRegistry.sol";
import {
    RoleRegistryClientUpgradeable
} from "./roleRegistry/RoleRegistryClientUpgradeable.sol";
import {
    PolicyRegistryClientUpgradeable
} from "./policyRegistry/PolicyRegistryClientUpgradeable.sol";

interface ICommodityTokenProxy {
    function getImplementation() external view returns (address);
}

/*
    @title CommodityToken
    @dev ERC20 Token representing real-asset backed token with upgradeability, registry-based access control, and pausing.
 */
contract CommodityToken is
    Initializable,
    UUPSUpgradeable,
    ERC20PermitUpgradeable,
    PausableUpgradeable,
    RoleRegistryClientUpgradeable,
    PolicyRegistryClientUpgradeable,
    IERC7943Fungible
{
    // ====================
    // Roles
    // ====================
    // @notice DEFAULT_ADMIN_ROLE is inherited from RoleRegistryClientUpgradeable.
    // @notice UPGRADER_ROLE is used when upgrading the authorized implementation
    // 0x189ab7a9244df0848122154315af71fe140f3db0fe014031783b0946b8c9d2e3;
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // @notice CANCEL_UPGRADE_ROLE cancels staged upgrades and clears expired ones
    // 0xa0324d41b94560df5693d4ed27201bafac752ef7def04ea6ee604ce06a181e87;
    bytes32 public constant CANCEL_UPGRADE_ROLE = keccak256("CANCEL_UPGRADE_ROLE");

    // @notice PAUSER_ROLE is used to pause the contract
    // 0x65d7a28e3265b37a6474929f336521b332c1681b933f6cb9f3376673440d862a;
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // @notice UNPAUSER_ROLE is used to unpause the contract
    // 0x427da25fe773164f88948d3e215c94b6554e2ed5e5f203a821c9f2f6131cf75a;
    bytes32 public constant UNPAUSER_ROLE = keccak256("UNPAUSER_ROLE");

    // @notice VAULT_MINTER_ROLE is used to mint tokens(backed by vault assets)
    // 0x98e4415ac43dc65a73fb377c77c834c9fba44fb3f81dc603d1f33e6023519e07;
    bytes32 public constant VAULT_MINTER_ROLE = keccak256("VAULT_MINTER_ROLE");

    // @notice MINTER_ROLE is used to mint tokens(usually for bridge minting)
    // 0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6;
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    // @notice BURNER_ROLE is used to burn tokens
    // 0x3c11d16cbaffd01df69ce1c404f6340ee057498f5f00246190ea54220576a848;
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");

    // @notice TOKEN_RISK_MANAGER_ROLE is used to manage risk-related functions
    // 0x456362d391fa22e9cf80e45f524019f0beb3d88e1e1b95b5d470aace20829c14;
    bytes32 public constant TOKEN_RISK_MANAGER_ROLE = keccak256("TOKEN_RISK_MANAGER_ROLE");

    // ====================
    // Policies
    // ====================
    bytes32 public constant TRANSFER_SENDER_POLICY =
        keccak256("TRANSFER_SENDER_POLICY");
    bytes32 public constant TRANSFER_RECEIVER_POLICY =
        keccak256("TRANSFER_RECEIVER_POLICY");
    bytes32 public constant TRANSFER_EXECUTOR_POLICY =
        keccak256("TRANSFER_EXECUTOR_POLICY");
    bytes32 public constant APPROVAL_OWNER_POLICY =
        keccak256("APPROVAL_OWNER_POLICY");
    bytes32 public constant APPROVAL_SPENDER_POLICY =
        keccak256("APPROVAL_SPENDER_POLICY");
    bytes32 public constant FORCED_TRANSFER_SOURCE_POLICY =
        keccak256("FORCED_TRANSFER_SOURCE_POLICY");
    bytes32 public constant FORCED_TRANSFER_RECEIVER_POLICY =
        keccak256("FORCED_TRANSFER_RECEIVER_POLICY");

    /// @custom:storage-location erc7201:kgold.storage.CommodityTokenPolicies
    struct CommodityTokenPolicyStorage {
        mapping(bytes32 scope => uint64 id) policyIds;
    }

    // keccak256(abi.encode(uint256(keccak256("kgold.storage.CommodityTokenPolicies")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant TOKEN_POLICY_STORAGE =
        0x3eae3bc16d045021540f7963d9a50fcd080e8172f52e97bf1977600d0c4b3400;

    error UnsupportedPolicyType(bytes32 policyScope);
    error ForcedTransferPolicyRequired(bytes32 policyScope);

    event PolicyUpdated(
        bytes32 indexed policyScope,
        uint64 oldPolicyId,
        uint64 newPolicyId
    );

    /// @notice Returns the configured policy ID, or zero if unset.
    /// @dev Zero means ALWAYS_ALLOW for regular transfers and approvals, but disables forced transfers.
    function policyId(bytes32 policyScope) public view returns (uint64) {
        _checkSupportedPolicyScope(policyScope);
        return _getCommodityTokenPolicyStorage().policyIds[policyScope];
    }

    /// @notice Assigns an existing policy to a supported token scope.
    /// @dev Global or token-local TOKEN_RISK_MANAGER_ROLE holders may change bindings.
    /// For policies other than registry built-ins, use the ID from a validated
    /// PolicyCreated/RolePolicyCreated event in the registry's actual creation receipt,
    /// or the return value of creation within the same transaction.
    /// Never bind IDs predicted from counters or preassigned before creation.
    /// Existence checks do not verify creation provenance, administrators or members.
    function updatePolicy(
        bytes32 policyScope,
        uint64 newPolicyId
    ) external onlyProxy onlyRole(TOKEN_RISK_MANAGER_ROLE) {
        _updatePolicy(policyScope, newPolicyId);
    }

    function _updatePolicy(bytes32 policyScope, uint64 newPolicyId) private {
        _checkSupportedPolicyScope(policyScope);
        _checkPolicyExists(newPolicyId);

        CommodityTokenPolicyStorage
            storage $ = _getCommodityTokenPolicyStorage();
        uint64 oldPolicyId = $.policyIds[policyScope];
        $.policyIds[policyScope] = newPolicyId;
        emit PolicyUpdated(policyScope, oldPolicyId, newPolicyId);
    }

    function _checkSupportedPolicyScope(
        bytes32 policyScope
    ) private pure {
        if (!(
            policyScope == TRANSFER_SENDER_POLICY ||
            policyScope == TRANSFER_RECEIVER_POLICY ||
            policyScope == TRANSFER_EXECUTOR_POLICY ||
            policyScope == APPROVAL_OWNER_POLICY ||
            policyScope == APPROVAL_SPENDER_POLICY ||
            policyScope == FORCED_TRANSFER_SOURCE_POLICY ||
            policyScope == FORCED_TRANSFER_RECEIVER_POLICY
        )) revert UnsupportedPolicyType(policyScope);
    }

    function _getCommodityTokenPolicyStorage()
        private
        pure
        returns (CommodityTokenPolicyStorage storage $)
    {
        assembly {
            $.slot := TOKEN_POLICY_STORAGE
        }
    }

    /// @custom:storage-location erc7201:kgold.storage.CommodityTokenTreasury
    struct CommodityTokenTreasuryStorage {
        address treasury;
    }

    // keccak256(abi.encode(uint256(keccak256("kgold.storage.CommodityTokenTreasury")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant TOKEN_TREASURY_STORAGE =
        0x7e7eccecc1c672d87f1f097302248bb3f6c5699a4cb934e97f7e6d467b248300;

    error InvalidTreasury(address treasury);
    event TreasuryInitialized(address indexed treasury);

    /// @notice Returns the Treasury address used to calculate circulating supply externally.
    /// @dev totalCirculating = totalSupply() - balanceOf(treasury()).
    function treasury() public view returns (address) {
        return _getCommodityTokenTreasuryStorage().treasury;
    }

    function _initializeTreasury(address treasury_) private onlyInitializing {
        if (treasury_.code.length == 0 || treasury_ == address(this))
            revert InvalidTreasury(treasury_);
        _getCommodityTokenTreasuryStorage().treasury = treasury_;
        emit TreasuryInitialized(treasury_);
    }

    function _getCommodityTokenTreasuryStorage()
        private
        pure
        returns (CommodityTokenTreasuryStorage storage $)
    {
        assembly {
            $.slot := TOKEN_TREASURY_STORAGE
        }
    }

    // ====================
    // Initializer
    // ====================
    /// @notice Commits this implementation to the auditor-reviewed legacy migration config.
    /// @dev keccak256(abi.encode(config)). Zero disables legacy reinitialize(), but
    /// does not prevent initialize() on a new proxy or subsequent staged upgrades.
    bytes32 public immutable REINITIALIZE_CONFIG_HASH;

    error InvalidReinitializeConfig();

    constructor(bytes32 reinitializeConfigHash_) {
        REINITIALIZE_CONFIG_HASH = reinitializeConfigHash_;
        _disableInitializers();
    }

    function initialize(
        address initialAdmin,
        string memory _name,
        string memory _symbol,
        address roleRegistry_,
        address policyRegistry_,
        address treasury_
    ) public initializer onlyProxy {
        require(
            initialAdmin != address(0),
            "CommodityToken: initial admin is zero"
        );
        __ERC20_init(_name, _symbol);

        // including initialize EIP712 domain separator
        __ERC20Permit_init(_name);
        __Pausable_init();
        __RoleRegistryClient_init(roleRegistry_);
        _checkDefaultAdmin(initialAdmin);
        __PolicyRegistryClient_init(policyRegistry_);
        _initializeTreasury(treasury_);
    }

    /// @dev Calldata only. The designated operators may be different accounts.
    struct ReinitializeConfig {
        address roleRegistry;
        address policyRegistry;
        address treasury;
        address expectedDefaultAdmin;
        address upgrader;
        address canceller;
        address pauser;
        address unpauser;
        address riskManager;
        uint64 senderPolicyId;
        uint64 receiverPolicyId;
        uint64 executorPolicyId;
        uint64 forcedSourcePolicyId;
        uint64 forcedReceiverPolicyId;
    }

    // OZ v5 AccessControl namespace used by the legacy CommodityToken.
    // Read-only migration access; never reuse or clear the legacy role storage.
    bytes32 private constant LEGACY_ACCESS_CONTROL_STORAGE =
        0x02dd7bc7dec4dceedda775e58dd541e08a116c6c53815c0bd028192f7b626800;

    /// @notice Migrates a legacy AccessControl token to preconfigured registries.
    /// @dev Execute as the calldata of the legacy upgradeToAndCall, atomically with
    /// the implementation change. The legacy UPGRADER_ROLE authenticates this call;
    /// the new registries cannot authorize their own installation. Roles and policy
    /// members must be prepared externally, including legacy frozen accounts.
    /// Except for registry built-ins, obtain policy IDs from validated
    /// PolicyCreated/RolePolicyCreated events in actual creation receipts from
    /// config.policyRegistry. Never predict or preassign these IDs; confirm them
    /// before hashing config for REINITIALIZE_CONFIG_HASH and deploying the implementation.
    /// The auditor must review the config committed by REINITIALIZE_CONFIG_HASH
    /// before approving this implementation. A different config requires a new
    /// implementation deployment and auditor approval.
    /// Existing ERC20, signature, pause and legacy audit state is left intact.
    /// Policy ID zero allows regular transfers but disables forced transfers;
    /// mintLimit remains zero on migration from the legacy implementation.
    /// This is not a registry setter.
    function reinitialize(
        ReinitializeConfig calldata config
    ) external onlyProxy reinitializer(2) {
        _checkLegacyUpgrader();

        if (
            REINITIALIZE_CONFIG_HASH == bytes32(0) ||
            keccak256(abi.encode(config)) != REINITIALIZE_CONFIG_HASH
        ) revert InvalidReinitializeConfig();

        __RoleRegistryClient_init(config.roleRegistry);
        if (
            config.expectedDefaultAdmin == address(0) ||
            roleRegistry().defaultAdmin() != config.expectedDefaultAdmin
        ) revert InvalidRoleRegistry(config.roleRegistry);
        _checkDefaultAdmin(config.expectedDefaultAdmin);
        __PolicyRegistryClient_init(config.policyRegistry);
        _initializeTreasury(config.treasury);

        _checkMigrationRole(UPGRADER_ROLE, config.upgrader);
        _checkMigrationRole(CANCEL_UPGRADE_ROLE, config.canceller);
        _checkMigrationRole(PAUSER_ROLE, config.pauser);
        _checkMigrationRole(UNPAUSER_ROLE, config.unpauser);
        _checkMigrationRole(TOKEN_RISK_MANAGER_ROLE, config.riskManager);

        emit RoleRegistryUpdated(address(0), config.roleRegistry);
        emit PolicyRegistryUpdated(address(0), config.policyRegistry);
        _updatePolicy(TRANSFER_SENDER_POLICY, config.senderPolicyId);
        _updatePolicy(TRANSFER_RECEIVER_POLICY, config.receiverPolicyId);
        _updatePolicy(TRANSFER_EXECUTOR_POLICY, config.executorPolicyId);
        _updatePolicy(FORCED_TRANSFER_SOURCE_POLICY, config.forcedSourcePolicyId);
        _updatePolicy(FORCED_TRANSFER_RECEIVER_POLICY, config.forcedReceiverPolicyId);
    }

    function _checkLegacyUpgrader() private view {
        // AccessControlStorage._roles[UPGRADER_ROLE].hasRole[_msgSender()].
        bytes32 roleSlot = keccak256(
            abi.encode(UPGRADER_ROLE, LEGACY_ACCESS_CONTROL_STORAGE)
        );
        bytes32 memberSlot = keccak256(abi.encode(_msgSender(), roleSlot));
        uint256 member;
        assembly {
            member := sload(memberSlot)
        }
        if (member != 1)
            revert AccessControlUnauthorizedAccount(_msgSender(), UPGRADER_ROLE);
    }

    function _checkMigrationRole(bytes32 role, address account) private view {
        if (account == address(0))
            revert AccessControlUnauthorizedAccount(account, role);
        _checkRole(role, account);
    }

    // ====================
    // Pause Functions
    // ====================
    // @notice Pause all token transfers and approvals
    // @dev Only accounts with the PAUSER_ROLE can call this function
    function pause() external onlyProxy onlyRole(PAUSER_ROLE) {
        _pause();
    }

    // @notice Unpause all token transfers and approvals
    // @dev Only accounts with the UNPAUSER_ROLE can call this function
    function unpause() external onlyProxy onlyRole(UNPAUSER_ROLE) {
        _unpause();
    }

    // ====================
    // Update ERC20 Hook
    // ====================
    function _update(
        address _from,
        address _to,
        uint256 _amount
    ) internal override whenNotPaused onlyProxy {
        // All transfer paths, including ERC-3009, use this hook. Mint/burn skip the zero-address side.
        if (_from != address(0)) {
            _checkTokenPolicy(TRANSFER_SENDER_POLICY, _from);
            _checkUnfrozenBalance(_from, _amount);
        }
        if (_to != address(0)) {
            _checkTokenPolicy(TRANSFER_RECEIVER_POLICY, _to);
        }
        _checkTokenPolicy(TRANSFER_EXECUTOR_POLICY, _msgSender());
        super._update(_from, _to, _amount);
    }

    /// @custom:storage-location erc7201:kgold.storage.CommodityTokenFreeze
    struct CommodityTokenFreezeStorage {
        mapping(address account => uint256 amount) frozen;
    }

    // keccak256(abi.encode(uint256(keccak256("kgold.storage.CommodityTokenFreeze")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant TOKEN_FREEZE_STORAGE =
        0x948128671cbd67686407c2ceb5cb07a35e6cbff4315948f90f0e19c50345ad00;

    error TreasuryFreezeForbidden();
    error TreasuryForcedTransferForbidden();

    function supportsInterface(
        bytes4 interfaceId
    ) public pure override returns (bool) {
        return
            interfaceId == type(IERC165).interfaceId ||
            interfaceId == type(IERC7943Fungible).interfaceId;
    }

    function getFrozenTokens(
        address account
    ) public view override returns (uint256) {
        return _getCommodityTokenFreezeStorage().frozen[account];
    }

    /// @notice Replaces the absolute frozen amount, including future holdings.
    /// @dev The configured Treasury cannot be targeted, including with amount zero.
    function setFrozenTokens(
        address account,
        uint256 amount
    ) external override onlyProxy onlyRole(TOKEN_RISK_MANAGER_ROLE) returns (bool) {
        _setFrozenTokens(account, amount);
        return true;
    }

    function canSend(address account) public view override returns (bool) {
        return _isTransferPolicyAuthorized(TRANSFER_SENDER_POLICY, account);
    }

    function canReceive(address account) public view override returns (bool) {
        return _isTransferPolicyAuthorized(TRANSFER_RECEIVER_POLICY, account);
    }

    /// @dev Includes the caller's executor policy, but not ERC-20 allowance/balance validity.
    /// Zero-address sides follow the mint/burn exemptions used by _update.
    /// Use canTransferFor to query on behalf of a different executor.
    function canTransfer(
        address from,
        address to,
        uint256 amount
    ) public view override returns (bool) {
        return canTransferFor(_msgSender(), from, to, amount);
    }

    /// @notice Checks transfer compliance for the specified executor, regardless of the query caller.
    /// @param executor The address that will directly call the token's transfer entry point.
    /// @dev Includes pause, sender/receiver policies and frozen amounts. Does not
    /// validate ERC-20 allowance, total balance sufficiency or address validity.
    /// This is a query only; it grants no authority to execute a transfer.
    function canTransferFor(
        address executor,
        address from,
        address to,
        uint256 amount
    ) public view returns (bool) {
        if (paused()) return false;
        if (from != address(0) && !canSend(from)) return false;
        if (to != address(0) && !canReceive(to)) return false;
        if (
            !_isTransferPolicyAuthorized(TRANSFER_EXECUTOR_POLICY, executor)
        ) return false;
        if (from != address(0)) {
            uint256 balance = balanceOf(from);
            // Insufficient total balance is an ERC-20 validation, not a compliance denial.
            if (amount <= balance && amount > _unfrozenBalance(from, balance))
                return false;
        }
        return true;
    }

    /// @notice Enforcement transfer: bypasses pause, regular sender/executor policy and allowance.
    /// @dev Requires nonzero source/receiver enforcement policies that authorize from/to.
    /// Regular receiver eligibility and ERC-20 address/balance checks remain mandatory.
    /// The configured Treasury cannot be a source, regardless of enforcement policies.
    /// Unfreezes seized holdings before Transfer, then restores unused future freezing.
    /// Self transfers restore the original frozen amount; the recipient's freezing is unchanged.
    function forcedTransfer(
        address from,
        address to,
        uint256 amount
    ) external override onlyProxy onlyRole(TOKEN_RISK_MANAGER_ROLE) returns (bool) {
        if (from == address(0)) revert ERC20InvalidSender(from);
        if (to == address(0)) revert ERC20InvalidReceiver(to);
        if (_isTreasury(from)) revert TreasuryForcedTransferForbidden();
        uint256 balance = balanceOf(from);
        if (amount > balance)
            revert ERC20InsufficientBalance(from, balance, amount);
        if (!canReceive(to)) revert ERC7943CannotReceive(to);
        _checkForcedTransferPolicy(FORCED_TRANSFER_SOURCE_POLICY, from);
        _checkForcedTransferPolicy(FORCED_TRANSFER_RECEIVER_POLICY, to);

        uint256 frozen = getFrozenTokens(from);
        uint256 unfrozen = balance > frozen ? balance - frozen : 0;
        uint256 finalFrozen = frozen;
        // All external checks are complete. Keep unfreeze, transfer and refreeze internal.
        if (amount > unfrozen) {
            _setFrozenTokens(from, balance - amount);
            if (from != to) finalFrozen -= amount - unfrozen;
        }
        super._update(from, to, amount);
        if (getFrozenTokens(from) != finalFrozen) {
            _setFrozenTokens(from, finalFrozen);
        }
        emit ForcedTransfer(from, to, amount);
        return true;
    }

    function _checkUnfrozenBalance(
        address account,
        uint256 amount
    ) private view {
        uint256 balance = balanceOf(account);
        if (amount > balance)
            revert ERC20InsufficientBalance(account, balance, amount);
        uint256 unfrozen = _unfrozenBalance(account, balance);
        if (amount > unfrozen) {
            revert ERC7943InsufficientUnfrozenBalance(
                account,
                amount,
                unfrozen
            );
        }
    }

    function _unfrozenBalance(
        address account,
        uint256 balance
    ) private view returns (uint256) {
        uint256 frozen = getFrozenTokens(account);
        return balance > frozen ? balance - frozen : 0;
    }

    function _setFrozenTokens(address account, uint256 amount) private {
        if (_isTreasury(account)) revert TreasuryFreezeForbidden();
        _getCommodityTokenFreezeStorage().frozen[account] = amount;
        emit Frozen(account, amount);
    }

    /// @dev Treasury is exempt from regular transfer policies. Other accounts fail
    /// closed on missing policies, registry reverts, or malformed return data.
    function _isTransferPolicyAuthorized(
        bytes32 scope,
        address account
    ) private view returns (bool) {
        if (_isTreasuryPolicyExempt(scope, account)) return true;
        uint64 id = _getCommodityTokenPolicyStorage().policyIds[scope];
        address registry = address(policyRegistry());
        if (
            !_registryBool(
                registry,
                abi.encodeCall(IPolicyRegistry.policyExists, (id))
            )
        ) return false;
        return
            _registryBool(
                registry,
                abi.encodeCall(IPolicyRegistry.isAuthorized, (id, account))
            );
    }

    function _registryBool(
        address registry,
        bytes memory callData
    ) private view returns (bool) {
        (bool success, bytes memory result) = registry.staticcall(callData);
        if (!success || result.length != 32) return false;
        uint256 value;
        assembly {
            value := mload(add(result, 32))
        }
        return value == 1;
    }

    function _getCommodityTokenFreezeStorage()
        private
        pure
        returns (CommodityTokenFreezeStorage storage $)
    {
        assembly {
            $.slot := TOKEN_FREEZE_STORAGE
        }
    }

    function _checkTokenPolicy(
        bytes32 policyScope,
        address account
    ) private view {
        if (_isTreasuryPolicyExempt(policyScope, account)) return;
        uint64 id = _getCommodityTokenPolicyStorage().policyIds[policyScope];
        // A Registry replacement must not silently allow an unknown BLOCKLIST ID.
        if (id != 0) _checkPolicyExists(id);
        _checkPolicy(id, account);
    }

    function _isTreasury(address account) private view returns (bool) {
        return account != address(0) && account == treasury();
    }

    /// @dev Exempts only Treasury's own regular transfer/approval eligibility.
    /// Counterparties, pause, roles, balances and enforcement policies still apply.
    function _isTreasuryPolicyExempt(
        bytes32 scope,
        address account
    ) private view returns (bool) {
        if (!_isTreasury(account)) return false;
        return
            scope == TRANSFER_SENDER_POLICY ||
            scope == TRANSFER_RECEIVER_POLICY ||
            scope == TRANSFER_EXECUTOR_POLICY ||
            scope == APPROVAL_OWNER_POLICY ||
            scope == APPROVAL_SPENDER_POLICY;
    }

    function _checkForcedTransferPolicy(bytes32 policyScope, address account) private view {
        uint64 id = _getCommodityTokenPolicyStorage().policyIds[policyScope];
        if (id == 0) revert ForcedTransferPolicyRequired(policyScope);
        _checkPolicyExists(id);
        _checkPolicy(id, account);
    }

    // ====================
    // Nonce Authorization (EIP712)
    // ====================
    // keccak256(abi.encode(uint256(keccak256(bytes("EIP712.USED_NONCE"))) - 1)) & ~bytes32(uint256(0xff));
    bytes32 private constant AUTHORIZATION_STATE_STORAGE =
        0xaedccaaf8ccffebfb1c1fab02788f133cca08385faadbe1e213b04d3cebadd00;

    struct AuthorizationStorage {
        mapping(address => mapping(bytes32 => bool)) usedNonces;
    }

    function _getUsedNoncesStorage()
        internal
        pure
        returns (AuthorizationStorage storage store)
    {
        bytes32 slot = AUTHORIZATION_STATE_STORAGE;
        assembly {
            store.slot := slot
        }
    }

    function authorizationState(
        address authorizer,
        bytes32 nonce
    ) external view returns (bool) {
        AuthorizationStorage storage store = _getUsedNoncesStorage();
        return store.usedNonces[authorizer][nonce];
    }

    function cancelAuthorization(
        address authorizer,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external onlyProxy {
        AuthorizationStorage storage store = _getUsedNoncesStorage();
        if (store.usedNonces[authorizer][nonce] == true) {
            revert InvalidAuthorization(authorizer, nonce);
        }

        // Verify Signature
        bytes32 structHash = keccak256(
            abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, authorizer, nonce)
        );

        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(hash, v, r, s);

        if (signer != authorizer) {
            revert InvalidSignature();
        }

        // Mark the nonce as used to prevent future use
        store.usedNonces[authorizer][nonce] = true;
        emit AuthorizationCanceled(authorizer, nonce);
    }

    error InvalidAuthorization(address authorizer, bytes32 nonce);

    /// @notice ERC-1271/EOA variant sharing cancellation state with the v,r,s API.
    function cancelAuthorization(address authorizer, bytes32 nonce, bytes calldata signature)
        external onlyProxy
    {
        AuthorizationStorage storage store = _getUsedNoncesStorage();
        if (store.usedNonces[authorizer][nonce]) revert InvalidAuthorization(authorizer, nonce);
        _checkSignature(authorizer, keccak256(abi.encode(
            CANCEL_AUTHORIZATION_TYPEHASH, authorizer, nonce
        )), signature);
        store.usedNonces[authorizer][nonce] = true;
        emit AuthorizationCanceled(authorizer, nonce);
    }

    /// @notice ERC-1271/EOA extension using the standard Permit typed data and nonce.
    function permit(address owner, address spender, uint256 value, uint256 deadline, bytes calldata signature)
        external onlyProxy
    {
        if (block.timestamp > deadline) revert ERC2612ExpiredSignature(deadline);
        _checkSignature(owner, keccak256(abi.encode(
            keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
            owner, spender, value, nonces(owner), deadline
        )), signature);
        _useNonce(owner);
        _approve(owner, spender, value);
    }

    error InvalidSignature();

    /// @dev Accept ECDSA regardless of account code, including EIP-7702 delegation,
    /// then fall back to ERC-1271 when recovery fails or yields a different signer.
    function _checkSignature(address signer, bytes32 structHash, bytes memory signature) private view {
        if (signer == address(0)) revert InvalidSignature();
        bytes32 digest = _hashTypedDataV4(structHash);
        (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecover(digest, signature);
        if (err == ECDSA.RecoverError.NoError && recovered == signer) return;

        // STATICCALL prevents the wallet from mutating token or wallet state during validation.
        (bool success, bytes memory result) = signer.staticcall(
            abi.encodeCall(IERC1271.isValidSignature, (digest, signature))
        );
        if (!success || result.length < 32 ||
            abi.decode(result, (bytes32)) != bytes32(IERC1271.isValidSignature.selector)
        ) revert InvalidSignature();
    }

    function _checkAuthorizationAvailable(
        address authorizer, bytes32 nonce, uint256 validAfter, uint256 validBefore
    ) private view {
        if (block.timestamp <= validAfter || block.timestamp >= validBefore ||
            _getUsedNoncesStorage().usedNonces[authorizer][nonce]
        ) revert InvalidAuthorization(authorizer, nonce);
    }

    // ====================
    // Mint Limit
    // ====================
    struct MintUsage {
        uint256 dayStart;
        uint256 accumulatedAmount;
    }

    /// @custom:storage-location erc7201:kgold.storage.CommodityTokenMint
    struct CommodityTokenMintStorage {
        uint256 mintLimit;
        // Shared by every MINTER_ROLE caller and recipient on this token proxy.
        MintUsage globalMintUsage;
    }

    // keccak256(abi.encode(uint256(keccak256("kgold.storage.CommodityTokenMint")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant TOKEN_MINT_STORAGE =
        0x394284f333a044aaa73c76afd1db36b9ee8503e7816e0f098eacc9a20cd6a200;

    error MintLimitExceed();

    event MintLimitUpdated(uint256 oldLimit, uint256 newLimit);

    /// @notice Returns the token-wide UTC daily mint limit, initially zero.
    function mintLimit() public view returns (uint256) {
        return _getCommodityTokenMintStorage().mintLimit;
    }

    /// @notice Sets the token-wide UTC daily limit for mint, in token base units.
    /// @dev Changing the limit does not reset accumulated usage; vaultMint is excluded.
    function setMintLimit(uint256 newLimit) external onlyProxy onlyRole(TOKEN_RISK_MANAGER_ROLE) {
        CommodityTokenMintStorage storage $ = _getCommodityTokenMintStorage();
        uint256 oldLimit = $.mintLimit;
        $.mintLimit = newLimit;
        emit MintLimitUpdated(oldLimit, newLimit);
    }

    function _getCommodityTokenMintStorage()
        private
        pure
        returns (CommodityTokenMintStorage storage $)
    {
        assembly {
            $.slot := TOKEN_MINT_STORAGE
        }
    }

    // ====================
    // ERC20 Functions(Permissioned)
    // ====================
    /// @notice Mints against the daily limit shared by all minters and recipients.
    function mint(
        address _to,
        uint256 _amount
    ) external onlyRole(MINTER_ROLE) onlyProxy {
        CommodityTokenMintStorage storage $ = _getCommodityTokenMintStorage();
        MintUsage storage usage = $.globalMintUsage;
        uint256 dayStart = block.timestamp - (block.timestamp % 1 days);
        if (usage.dayStart != dayStart) {
            usage.dayStart = dayStart;
            usage.accumulatedAmount = 0;
        }
        // Check before addition so exceeding the limit always uses the custom error.
        if (usage.accumulatedAmount > $.mintLimit ||
            _amount > $.mintLimit - usage.accumulatedAmount) revert MintLimitExceed();
        usage.accumulatedAmount += _amount;
        _mint(_to, _amount);
        emit Minted(_to, _amount);
    }

    function burn(uint256 _amount) external onlyRole(BURNER_ROLE) onlyProxy {
        _burn(_msgSender(), _amount);
        emit Burned(_msgSender(), _amount);
    }

    // ====================
    // Vault Mint
    // ====================

    bytes32 public constant UNISSUED_KGLD = keccak256("UNISSUED_KGLD");

    /// @notice Mints vault-backed tokens into Treasury's UNISSUED_KGLD bucket.
    /// @dev Assign VAULT_MINTER_ROLE to the multisig that authorizes vault issuance.
    /// The Token Proxy must hold TREASURY_MANAGER_ROLE for the configured Treasury.
    /// Leave UNISSUED_KGLD's deposit policy at ID 0: Treasury automatically allows
    /// deposits by managers without a separate policy membership grant. A nonzero
    /// deposit policy, if configured later, still applies to the Token Proxy.
    /// Mint to this proxy, approve only this deposit, then clear any allowance left.
    /// Pause, transfer policies and frozen-balance checks still apply; the bridge
    /// mint limit is not consumed. A failed deposit rolls back the entire issuance.
    function vaultMint(uint256 amount)
        external onlyProxy onlyRole(VAULT_MINTER_ROLE)
    {
        address treasuryAddress = treasury();
        _mint(address(this), amount);
        _approve(address(this), treasuryAddress, amount, false);
        ITreasury(treasuryAddress).deposit(address(this), UNISSUED_KGLD, amount);
        _approve(address(this), treasuryAddress, 0, false);
        emit Minted(treasuryAddress, amount);
    }

    // ====================
    // ERC20 Functions(Public)
    // ====================
    function name() public view override returns (string memory) {
        return super.name();
    }

    function symbol() public view override returns (string memory) {
        return super.symbol();
    }

    function decimals() public view override returns (uint8) {
        return super.decimals();
    }

    function _approve(
        address _owner,
        address _spender,
        uint256 _amount,
        bool emitEvent
    ) internal override onlyProxy {
        // When amount is zero, it means the approval is being revoked, so we allow it even when paused
        // For any non-zero approval, the contract must not be paused
        if (_amount > 0) {
            _requireNotPaused();
        }

        if (_owner == address(0)) {
            revert ERC20InvalidApprover(address(0));
        }
        if (_spender == address(0)) {
            revert ERC20InvalidSpender(address(0));
        }

        // approve/permit pass emitEvent=true; allowance spending passes false.
        // Revocation and spending existing allowances do not require approval policies.
        if (emitEvent && _amount > 0) {
            _checkTokenPolicy(APPROVAL_OWNER_POLICY, _owner);
            _checkTokenPolicy(APPROVAL_SPENDER_POLICY, _spender);
        }

        AllowanceNonceStorage
            storage allowanceStorage = _getAllowanceNonceStorage();
        uint256 currentNonce = allowanceStorage.nonce[_owner];
        allowanceStorage.allowance[_owner][currentNonce][_spender] = _amount;

        if (emitEvent) {
            emit Approval(_owner, _spender, _amount);
        }
    }

    function balanceOf(
        address _account
    ) public view override returns (uint256) {
        return super.balanceOf(_account);
    }

    // Incrementing an owner's epoch invalidates all allowances from previous epochs.
    // Allowance : address user => uint256 nonce => address spender => uint256 amount
    struct AllowanceNonceStorage {
        mapping(address => uint256) nonce;
        mapping(address => mapping(uint256 => mapping(address => uint256))) allowance;
    }

    // allowanceNonceStorage slot
    // keccak256(abi.encode(uint256(keccak256(bytes("ALLOWANCE_NONCE_STORAGE"))) - 1)) & ~bytes32(uint256(0xff));
    bytes32 private constant allowanceNonceStorage =
        0xea41d1798cd34728e904635e32c4b899afc3c827783776b2bfabce68dbf12100;

    function _getAllowanceNonceStorage()
        private
        pure
        returns (AllowanceNonceStorage storage store)
    {
        assembly {
            store.slot := allowanceNonceStorage
        }
    }

    /// @notice Revokes every allowance granted by the caller by advancing its epoch.
    /// @dev Independent of pause, freezing, policies and registry availability.
    /// Permit nonces and ERC-3009 authorizations are unchanged; unused signatures
    /// remain subject to their existing validity rules.
    function revokeAll() external onlyProxy {
        address owner = _msgSender();
        uint256 newEpoch = _increaseAllowanceNonce(owner);
        emit AllowancesRevoked(owner, newEpoch);
    }

    function _increaseAllowanceNonce(address _owner) internal returns (uint256) {
        AllowanceNonceStorage
            storage allowanceStorage = _getAllowanceNonceStorage();
        return ++allowanceStorage.nonce[_owner];
    }

    function allowance(
        address _owner,
        address _spender
    ) public view override returns (uint256) {
        AllowanceNonceStorage
            storage allowanceStorage = _getAllowanceNonceStorage();

        uint256 currentNonce = allowanceStorage.nonce[_owner];

        return allowanceStorage.allowance[_owner][currentNonce][_spender];
    }

    function transfer(
        address to,
        uint256 value
    ) public override whenNotPaused onlyProxy returns (bool) {
        super.transfer(to, value);
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 value
    ) public override whenNotPaused onlyProxy returns (bool) {
        super.transferFrom(from, to, value);
        return true;
    }

    // ====================
    // Timelocked upgrade functions
    // ====================
    // Fixed durations; retain the existing constant getter names for ABI compatibility.
    uint256 public constant DEFAULT_UPGRADE_TIMELOCK = 2 days;
    uint256 public constant DEFAULT_UPGRADE_FINALIZE_WINDOW = 3 days;

    struct PendingUpgrade {
        address implementation;
        bytes data;
        uint256 validAfter;
        uint256 validBefore;
    }

    /// @custom:storage-location erc7201:kgold.storage.CommodityTokenUpgrade
    struct CommodityTokenUpgradeStorage {
        PendingUpgrade pending;
        // Deprecated timing fields retained to preserve the following storage slots.
        uint256 timelock;
        uint256 finalizeWindow;
        bool finalizing;
    }

    // keccak256(abi.encode(uint256(keccak256("kgold.storage.CommodityTokenUpgrade")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant TOKEN_UPGRADE_STORAGE =
        0xe808b9c81880e29eb631eaeffecee5443bbea6bd10b833562c14f98ecd6bd600;

    error InvalidImplementation(address implementation);
    error NoPendingUpgrade();
    error UpgradeNotReady(uint256 validAfter);
    error UpgradeExpired(uint256 validBefore);
    error DirectUpgradeDisabled();
    error UpgradeAlreadyFinalizing();
    error UpgradeAlreadyStaged();

    event NewImplementationStaged(
        address indexed implementation,
        bytes32 indexed dataHash,
        uint256 validAfter,
        uint256 validBefore
    );
    event UpgradeFinalized(
        address indexed implementation,
        bytes32 indexed dataHash
    );
    event StagedUpgradeCancelled(
        address indexed implementation,
        bytes32 indexed dataHash
    );

    function pendingUpgrade() external view returns (PendingUpgrade memory) {
        return _getCommodityTokenUpgradeStorage().pending;
    }

    /// @notice Fixed waiting period before a newly staged upgrade can execute.
    function upgradeTimelock() public pure returns (uint256) {
        return DEFAULT_UPGRADE_TIMELOCK;
    }

    /// @notice Fixed execution window after the waiting period ends.
    function upgradeFinalizeWindow() public pure returns (uint256) {
        return DEFAULT_UPGRADE_FINALIZE_WINDOW;
    }

    /// @notice Stages the exact implementation and migration calldata for execution after the timelock.
    function stageNewImplementation(
        address newImplementation,
        bytes calldata data
    ) external onlyProxy onlyRole(UPGRADER_ROLE) {
        CommodityTokenUpgradeStorage storage $ = _getCommodityTokenUpgradeStorage();
        if ($.finalizing) revert UpgradeAlreadyFinalizing();
        if ($.pending.implementation != address(0) && block.timestamp < $.pending.validBefore)
            revert UpgradeAlreadyStaged();
        if (
            newImplementation == address(0) ||
            newImplementation.code.length == 0 ||
            ICommodityTokenProxy(address(this)).getImplementation() ==
            newImplementation
        ) revert InvalidImplementation(newImplementation);

        uint256 validAfter = block.timestamp + upgradeTimelock();
        uint256 validBefore = validAfter + upgradeFinalizeWindow();
        $.pending = PendingUpgrade({
            implementation: newImplementation,
            data: data,
            validAfter: validAfter,
            validBefore: validBefore
        });
        emit NewImplementationStaged(
            newImplementation,
            keccak256(data),
            validAfter,
            validBefore
        );
    }

    /// @notice Cancels a live staged upgrade or deletes an expired staged upgrade.
    function cancelStagedUpgrade() external onlyProxy onlyRole(CANCEL_UPGRADE_ROLE) {
        CommodityTokenUpgradeStorage storage $ = _getCommodityTokenUpgradeStorage();
        if ($.finalizing) revert UpgradeAlreadyFinalizing();
        address implementation = $.pending.implementation;
        if (implementation == address(0)) revert NoPendingUpgrade();
        bytes32 dataHash = keccak256($.pending.data);
        delete $.pending;
        emit StagedUpgradeCancelled(implementation, dataHash);
    }

    function finalizeUpgrade() external onlyProxy onlyRole(UPGRADER_ROLE) {
        CommodityTokenUpgradeStorage
            storage $ = _getCommodityTokenUpgradeStorage();
        if ($.finalizing) revert UpgradeAlreadyFinalizing();
        PendingUpgrade storage pending = $.pending;
        address implementation = pending.implementation;
        if (implementation == address(0)) revert NoPendingUpgrade();
        if (block.timestamp < pending.validAfter)
            revert UpgradeNotReady(pending.validAfter);
        if (block.timestamp >= pending.validBefore)
            revert UpgradeExpired(pending.validBefore);

        bytes memory data = pending.data;
        bytes32 dataHash = keccak256(data);
        $.finalizing = true;
        super.upgradeToAndCall(implementation, data);
        delete $.pending;
        $.finalizing = false;
        emit UpgradeFinalized(implementation, dataHash);
    }

    function upgradeToAndCall(
        address,
        bytes memory
    ) public payable override onlyProxy {
        revert DirectUpgradeDisabled();
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal view override onlyProxy onlyRole(UPGRADER_ROLE) {
        CommodityTokenUpgradeStorage
            storage $ = _getCommodityTokenUpgradeStorage();
        if (!$.finalizing || $.pending.implementation != newImplementation)
            revert InvalidImplementation(newImplementation);
    }

    function _getCommodityTokenUpgradeStorage()
        private
        pure
        returns (CommodityTokenUpgradeStorage storage $)
    {
        assembly {
            $.slot := TOKEN_UPGRADE_STORAGE
        }
    }

    // ====================
    // EIP3009
    // ====================

    // 0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267;
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH =
        keccak256(
            "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
        );

    // 0xd099cc98ef71107a616c4f0f941f04c322d8e254fe26b3c6668db87aae413de8;
    bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH =
        keccak256(
            "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
        );

    bytes32 public constant CANCEL_AUTHORIZATION_TYPEHASH =
        keccak256("CancelAuthorization(address authorizer,bytes32 nonce)");

    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenNotPaused onlyProxy {
        AuthorizationStorage storage store = _getUsedNoncesStorage();
        // Invalid intervals, time boundaries, and consumed nonces share one error.
        if (
            block.timestamp <= validAfter ||
            block.timestamp >= validBefore ||
            store.usedNonces[from][nonce]
        ) {
            revert InvalidAuthorization(from, nonce);
        }

        // Verify Signature
        bytes32 structHash = keccak256(
            abi.encode(
                TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
                from,
                to,
                value,
                validAfter,
                validBefore,
                nonce
            )
        );

        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(hash, v, r, s);

        if (signer != from) {
            revert InvalidSignature();
        }

        // Mark the nonce as used
        store.usedNonces[from][nonce] = true;
        emit AuthorizationUsed(signer, nonce);

        _transfer(from, to, value);
    }

    error CallerIsNotRecipient();
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenNotPaused onlyProxy {
        // check if msg.sender is the recipient
        if (to != msg.sender) {
            revert CallerIsNotRecipient();
        }

        AuthorizationStorage storage store = _getUsedNoncesStorage();
        // Invalid intervals, time boundaries, and consumed nonces share one error.
        if (
            block.timestamp <= validAfter ||
            block.timestamp >= validBefore ||
            store.usedNonces[from][nonce]
        ) {
            revert InvalidAuthorization(from, nonce);
        }

        // Verify Signature
        bytes32 structHash = keccak256(
            abi.encode(
                RECEIVE_WITH_AUTHORIZATION_TYPEHASH,
                from,
                to,
                value,
                validAfter,
                validBefore,
                nonce
            )
        );

        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(hash, v, r, s);

        if (signer != from) {
            revert InvalidSignature();
        }

        // Mark the nonce as used
        store.usedNonces[from][nonce] = true;
        emit AuthorizationUsed(signer, nonce);

        _transfer(from, to, value);
    }

    // ====================
    // ERC-1271 / EOA authorization overloads
    // ====================
    function transferWithAuthorization(
        address from, address to, uint256 value, uint256 validAfter,
        uint256 validBefore, bytes32 nonce, bytes calldata signature
    ) external whenNotPaused onlyProxy {
        _transferWithContractAuthorization(
            TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce, signature
        );
    }

    function receiveWithAuthorization(
        address from, address to, uint256 value, uint256 validAfter,
        uint256 validBefore, bytes32 nonce, bytes calldata signature
    ) external whenNotPaused onlyProxy {
        if (to != _msgSender()) revert CallerIsNotRecipient();
        _transferWithContractAuthorization(
            RECEIVE_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce, signature
        );
    }

    function _transferWithContractAuthorization(
        bytes32 typeHash, address from, address to, uint256 value,
        uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes memory signature
    ) private {
        _checkAuthorizationAvailable(from, nonce, validAfter, validBefore);
        _checkSignature(from, keccak256(abi.encode(
            typeHash, from, to, value, validAfter, validBefore, nonce
        )), signature);
        _getUsedNoncesStorage().usedNonces[from][nonce] = true;
        emit AuthorizationUsed(from, nonce);
        _transfer(from, to, value);
    }

    // ====================
    // Events
    // ====================
    event AllowancesRevoked(address indexed owner, uint256 newEpoch);
    event Minted(address indexed to, uint256 amount);
    event Burned(address indexed from, uint256 amount);
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);
    event AuthorizationCanceled(
        address indexed authorizer,
        bytes32 indexed nonce
    );
}
