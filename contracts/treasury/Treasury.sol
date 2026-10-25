// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {
    ReentrancyGuardUpgradeable
} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {PolicyRegistryClientUpgradeable} from "../policyRegistry/PolicyRegistryClientUpgradeable.sol";
import {IPolicyRegistry} from "../policyRegistry/IPolicyRegistry.sol";
import {IRoleAdminPolicyRegistry} from "../policyRegistry/IRoleAdminPolicyRegistry.sol";
import {ITreasury} from "../controller/ITreasury.sol";

interface ITreasuryBurnableToken {
    function burn(uint256 amount) external;
}

/// @notice Custody with per-token bucket accounting; buckets are not user balances.
/// @dev Initialize through TreasuryProxy with the shared registries. Supports exact-amount ERC-20
/// transfers only; fee-on-transfer and rebasing tokens are not supported.
contract Treasury is PolicyRegistryClientUpgradeable, ReentrancyGuardUpgradeable, UUPSUpgradeable, ITreasury {
    using SafeERC20 for IERC20;

    // DEFAULT_ADMIN_ROLE is inherited from RoleRegistryClientUpgradeable.
    // Its global holder may acknowledge a backing deficit by writing off bucket allocations.
    // The roles below accept global or Treasury-proxy-local grants.

    /// @notice Deposits its own tokens, allocates unallocated holdings, withdraws, moves buckets and burns assets.
    /// @dev Bucket policies also apply, including to the combined depositAndWithdraw operation.
    bytes32 public constant TREASURY_MANAGER_ROLE =
        keccak256("TREASURY_MANAGER_ROLE");

    /// @notice Binds deposit/withdraw policies to buckets and sets the all-buckets override policy.
    bytes32 public constant TREASURY_RISK_MANAGER_ROLE = keccak256("TREASURY_RISK_MANAGER_ROLE");

    /// @notice Stages implementation upgrades and finalizes them within the allowed execution window.
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /// @notice Cancels staged upgrades or clears expired upgrade proposals.
    bytes32 public constant CANCEL_UPGRADE_ROLE = keccak256("CANCEL_UPGRADE_ROLE");

    bytes32 public constant DEPOSIT = keccak256("DEPOSIT");
    bytes32 public constant WITHDRAW = keccak256("WITHDRAW");
    /// @notice Virtual bucket for unallocated holdings; only valid as a bucketTransfer source.
    bytes32 public constant UNALLOCATED_BUCKET = bytes32(0);

    // Registry built-ins have no administrator; bindings require both expected admin values to be zero.
    uint64 private constant ALWAYS_ALLOW_POLICY = 0;
    uint64 private constant ALWAYS_BLOCK_POLICY =
        (uint64(IPolicyRegistry.PolicyType.ALLOWLIST) << 56) | 1;

    /// @custom:storage-location erc7201:kgold.storage.Treasury
    struct TreasuryStorage {
        // Only regular buckets have stored balances; use bucketUnallocated for the virtual bucket.
        mapping(address token => mapping(bytes32 bucket => uint256)) bucketAmount;
        mapping(address token => uint256) bucketAllocated;
        // Keys are keccak256(abi.encode(bucket, action)), shared across tokens.
        // Zero allows deposits but grants no withdrawal authority.
        mapping(bytes32 bucketKey => uint64 policyId) bucketPolicyIds;
        uint64 allBucketsPolicyId;
    }

    // keccak256(abi.encode(uint256(keccak256("kgold.storage.Treasury")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant TREASURY_STORAGE =
        0x40cadce535afed919571d1f7e84e4ce5806fd89d76e18223e308ad565d413e00;

    error InvalidToken(address token);
    error InvalidAccount(address account);
    error InvalidBucket(bytes32 bucket);
    error ZeroAmount();
    error SameBucketNotAllowed(bytes32 bucket);
    error WithdrawPolicyRequired(bytes32 bucket);
    error BucketAccessDenied(bytes32 bucket, address account);
    error InvalidPolicyAdminArguments();
    error PolicyAdminMismatch(uint64 policyId);
    error InsufficientBucketBalance(
        address token,
        bytes32 bucket,
        uint256 available,
        uint256 requested
    );
    error InsufficientUnallocatedBalance(
        address token,
        uint256 available,
        uint256 requested
    );
    error InsufficientBacking(
        address token,
        uint256 balance,
        uint256 allocated
    );
    error EmptyLossBuckets();
    error NoBackingDeficit(address token, uint256 balance, uint256 allocated);
    error UncoveredBackingDeficit(address token, uint256 remainingDeficit);
    error UnexpectedTokenBalance(
        address token,
        address account,
        uint256 expected,
        uint256 actual
    );

    event BucketPolicyUpdated(
        bytes32 indexed bucketKey,
        uint64 oldPolicyId,
        uint64 newPolicyId
    );
    event AllBucketsPolicyUpdated(uint64 oldPolicyId, uint64 newPolicyId);
    event Deposited(
        address indexed token,
        bytes32 indexed bucket,
        address indexed depositFrom,
        uint256 amount,
        address operator
    );
    event Withdrawn(
        address indexed token,
        bytes32 indexed bucket,
        address indexed depositTo,
        uint256 amount,
        address operator
    );
    event BucketTransferred(
        address indexed token,
        bytes32 indexed bucketFrom,
        bytes32 indexed bucketTo,
        uint256 amount,
        address operator
    );
    event BucketBurned(
        address indexed token,
        bytes32 indexed bucket,
        uint256 amount,
        address operator
    );
    event BucketAllocationWrittenOff(
        address indexed token,
        bytes32 indexed bucket,
        uint256 amount,
        address operator
    );
    event BucketAllocatedRepaired(
        address indexed token,
        uint256 oldAllocated,
        uint256 newAllocated,
        address indexed operator
    );

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address roleRegistry_,
        address policyRegistry_
    ) external initializer onlyProxy {
        __RoleRegistryClient_init(roleRegistry_);
        __PolicyRegistryClient_init(policyRegistry_);
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();
    }

    function bucketAmount(address token, bytes32 bucket) public view returns (uint256) {
        return _getTreasuryStorage().bucketAmount[token][bucket];
    }

    function bucketAllocated(address token) public view returns (uint256) {
        return _getTreasuryStorage().bucketAllocated[token];
    }

    function bucketPolicyIds(bytes32 bucketKey) public view returns (uint64 policyId) {
        return _getTreasuryStorage().bucketPolicyIds[bucketKey];
    }

    function allBucketsPolicyId() public view returns (uint64) {
        return _getTreasuryStorage().allBucketsPolicyId;
    }

    /// @notice Actual holdings that have not been assigned to a bucket.
    /// @dev Reverts on a backing deficit, e.g. after an external forced transfer.
    function bucketUnallocated(address token) public view returns (uint256) {
        return _backedBalance(token) - bucketAllocated(token);
    }

    /// @notice Returns the deterministic key used to bind a policy to a bucket/action pair.
    function getBucketPolicyKey(bytes32 bucket, bytes32 action) public pure returns (bytes32) {
        return keccak256(abi.encode(bucket, action));
    }

    /// @notice Binds a withdrawal policy; zero removes the bucket's withdrawal authority.
    /// @dev Checks the expected administrator; see _checkPolicyAdmin for argument conventions.
    function setBucketWithdrawPolicy(
        bytes32 bucket, uint64 policyId, address expectedAdmin, bytes32 expectedAdminRole
    )
        external onlyProxy nonReentrant onlyRole(TREASURY_RISK_MANAGER_ROLE)
    {
        _checkPolicyAdmin(policyId, expectedAdmin, expectedAdminRole);
        _setBucketPolicy(getBucketPolicyKey(bucket, WITHDRAW), policyId);
    }

    /// @notice Binds a deposit policy; zero restores the default permission for managers.
    /// @dev Checks the expected administrator; see _checkPolicyAdmin for argument conventions.
    function setBucketDepositPolicy(
        bytes32 bucket, uint64 policyId, address expectedAdmin, bytes32 expectedAdminRole
    )
        external onlyProxy nonReentrant onlyRole(TREASURY_RISK_MANAGER_ROLE)
    {
        _checkPolicyAdmin(policyId, expectedAdmin, expectedAdminRole);
        _setBucketPolicy(getBucketPolicyKey(bucket, DEPOSIT), policyId);
    }

    /// @notice Sets the policy whose authorized managers may access every bucket.
    /// @dev Zero disables this override; policy types, including blocklists, are unrestricted.
    /// Checks the expected administrator; see _checkPolicyAdmin for argument conventions.
    function setAllBucketsPolicy(uint64 policyId, address expectedAdmin, bytes32 expectedAdminRole)
        external onlyProxy nonReentrant onlyRole(TREASURY_RISK_MANAGER_ROLE)
    {
        _checkPolicyAdmin(policyId, expectedAdmin, expectedAdminRole);
        TreasuryStorage storage $ = _getTreasuryStorage();
        uint64 oldPolicyId = $.allBucketsPolicyId;
        $.allBucketsPolicyId = policyId;
        emit AllBucketsPolicyUpdated(oldPolicyId, policyId);
    }

    /// @dev Address policies require (admin, 0); role policies require (address(0), adminRole).
    /// A zero adminRole is DEFAULT_ADMIN_ROLE. Built-ins require (address(0), bytes32(0)).
    /// Checks only the current administrator, not creation provenance, members or composite children.
    /// Use the ID from the actual creation receipt or same-transaction return value, never a predicted ID.
    function _checkPolicyAdmin(
        uint64 policyId, address expectedAdmin, bytes32 expectedAdminRole
    ) internal view {
        if (expectedAdmin != address(0) && expectedAdminRole != bytes32(0)) {
            revert InvalidPolicyAdminArguments();
        }

        _checkPolicyExists(policyId);

        if (policyId == ALWAYS_ALLOW_POLICY || policyId == ALWAYS_BLOCK_POLICY) {
            if (expectedAdmin != address(0) || expectedAdminRole != bytes32(0)) {
                revert InvalidPolicyAdminArguments();
            }
            return;
        }

        IRoleAdminPolicyRegistry registry = IRoleAdminPolicyRegistry(address(policyRegistry()));
        if (expectedAdmin != address(0)) {
            if (registry.isRolePolicy(policyId) || registry.policyAdmin(policyId) != expectedAdmin) {
                revert PolicyAdminMismatch(policyId);
            }
        } else {
            if (!registry.isRolePolicy(policyId) || registry.policyAdminRole(policyId) != expectedAdminRole) {
                revert PolicyAdminMismatch(policyId);
            }
        }
    }

    function _setBucketPolicy(bytes32 bucketKey, uint64 policyId) internal {
        _checkPolicyExists(policyId);
        TreasuryStorage storage $ = _getTreasuryStorage();
        uint64 oldPolicyId = $.bucketPolicyIds[bucketKey];
        $.bucketPolicyIds[bucketKey] = policyId;
        emit BucketPolicyUpdated(bucketKey, oldPolicyId, policyId);
    }

    /// @notice Deposits only the calling manager's tokens using its allowance to Treasury.
    /// @dev An unset/ALWAYS_ALLOW deposit policy permits the operation.
    function deposit(
        address token,
        bytes32 bucket,
        uint256 amount
    ) external override onlyProxy nonReentrant onlyRole(TREASURY_MANAGER_ROLE) {
        _deposit(token, bucket, amount);
    }

    /// @notice Withdraws assets when the calling manager has global or bucket authority.
    function withdraw(
        address depositTo,
        address token,
        bytes32 bucket,
        uint256 amount
    ) external override onlyProxy nonReentrant onlyRole(TREASURY_MANAGER_ROLE) {
        _withdraw(depositTo, token, bucket, amount);
    }

    /// @notice Deposits the calling manager's tokens, then withdraws from another bucket, atomically.
    /// @dev Each leg has its own token and amount and checks the calling manager's policy.
    /// Equal buckets are forbidden even for different tokens. Both legs revert if either fails.
    function depositAndWithdraw(
        address depositToken,
        bytes32 depositBucket,
        uint256 depositAmount,
        address withdrawTo,
        address withdrawToken,
        bytes32 withdrawBucket,
        uint256 withdrawAmount
    ) external override onlyProxy nonReentrant onlyRole(TREASURY_MANAGER_ROLE) {
        if (depositBucket == withdrawBucket) revert SameBucketNotAllowed(depositBucket);
        _deposit(depositToken, depositBucket, depositAmount);
        _withdraw(withdrawTo, withdrawToken, withdrawBucket, withdrawAmount);
    }

    function _deposit(address token, bytes32 bucket, uint256 amount) internal {
        _checkRegularBucket(bucket);
        if (amount == 0) revert ZeroAmount();
        address depositFrom = _msgSender();
        _checkDepositPolicy(bucket, _msgSender());

        uint256 balance = _backedBalance(token);
        IERC20(token).safeTransferFrom(depositFrom, address(this), amount);
        _requireBalance(token, address(this), balance + amount);

        TreasuryStorage storage $ = _getTreasuryStorage();
        $.bucketAmount[token][bucket] += amount;
        $.bucketAllocated[token] += amount;
        emit Deposited(token, bucket, depositFrom, amount, _msgSender());
    }

    function _withdraw(address depositTo, address token, bytes32 bucket, uint256 amount) internal {
        _checkRegularBucket(bucket);
        if (amount == 0) revert ZeroAmount();
        if (depositTo == address(0) || depositTo == address(this) || depositTo == token)
            revert InvalidAccount(depositTo);
        _checkWithdrawPolicy(bucket, _msgSender());
        uint256 balance = _backedBalance(token);
        uint256 recipientBalance = IERC20(token).balanceOf(depositTo);
        _debitBucket(token, bucket, amount);
        _getTreasuryStorage().bucketAllocated[token] -= amount;

        IERC20(token).safeTransfer(depositTo, amount);
        _requireBalance(token, address(this), balance - amount);
        _requireBalance(token, depositTo, recipientBalance + amount);
        emit Withdrawn(token, bucket, depositTo, amount, _msgSender());
    }

    /// @notice Moves one token's allocation between buckets without transferring tokens.
    /// @dev UNALLOCATED_BUCKET may be the source to allocate existing holdings into a regular bucket.
    /// Both paths require source withdrawal and destination deposit authority for the caller.
    function bucketTransfer(
        address token,
        bytes32 bucketFrom,
        bytes32 bucketTo,
        uint256 amount
    ) public override onlyProxy nonReentrant onlyRole(TREASURY_MANAGER_ROLE) {
        _checkRegularBucket(bucketTo);
        if (bucketFrom == bucketTo) revert SameBucketNotAllowed(bucketFrom);
        if (amount == 0) revert ZeroAmount();
        _checkWithdrawPolicy(bucketFrom, _msgSender());
        _checkDepositPolicy(bucketTo, _msgSender());
        uint256 balance = _backedBalance(token);
        TreasuryStorage storage $ = _getTreasuryStorage();
        if (bucketFrom == UNALLOCATED_BUCKET) {
            uint256 unallocated = balance - $.bucketAllocated[token];
            if (amount > unallocated)
                revert InsufficientUnallocatedBalance(token, unallocated, amount);
            $.bucketAllocated[token] += amount;
        } else {
            _debitBucket(token, bucketFrom, amount);
        }
        $.bucketAmount[token][bucketTo] += amount;
        emit BucketTransferred(
            token,
            bucketFrom,
            bucketTo,
            amount,
            _msgSender()
        );
    }

    /// @notice Burns actual treasury holdings and debits their bucket allocation.
    /// @dev Withdrawal policy checks the caller. The token must implement burn(uint256).
    /// For CommodityToken, grant its BURNER_ROLE to this Treasury contract.
    function burnBucket(
        address token,
        bytes32 bucket,
        uint256 amount
    ) external override onlyProxy nonReentrant onlyRole(TREASURY_MANAGER_ROLE) {
        _checkRegularBucket(bucket);
        if (amount == 0) revert ZeroAmount();
        _checkWithdrawPolicy(bucket, _msgSender());
        uint256 balance = _backedBalance(token);
        _debitBucket(token, bucket, amount);
        _getTreasuryStorage().bucketAllocated[token] -= amount;

        ITreasuryBurnableToken(token).burn(amount);
        _requireBalance(token, address(this), balance - amount);
        emit BucketBurned(token, bucket, amount, _msgSender());
    }

    /// @notice Writes off a backing deficit from the supplied buckets in priority order.
    /// @dev Global default admin only; bucket policies are not consulted. No tokens move.
    /// The deficit is computed from the actual balance, never supplied by the caller.
    /// Zero-balance/duplicate buckets contribute only their remaining allocation. Every supplied
    /// bucket must be regular, even after the deficit is covered. Insufficient coverage
    /// reverts all deductions and events. Controller redemption obligations are unchanged.
    /// @param token Token whose actual Treasury balance is below its total allocation.
    /// @param lossBuckets Nonempty ordered list of regular buckets bearing the loss.
    function emergencyRepairBucketAllocated(
        address token,
        bytes32[] calldata lossBuckets
    ) external onlyProxy nonReentrant {
        _checkDefaultAdmin(_msgSender());
        if (token.code.length == 0) revert InvalidToken(token);
        if (lossBuckets.length == 0) revert EmptyLossBuckets();

        TreasuryStorage storage $ = _getTreasuryStorage();
        uint256 balance = IERC20(token).balanceOf(address(this));
        uint256 allocated = $.bucketAllocated[token];
        if (balance >= allocated) revert NoBackingDeficit(token, balance, allocated);
        uint256 remainingDeficit = allocated - balance;

        for (uint256 i; i < lossBuckets.length; ++i) {
            bytes32 bucket = lossBuckets[i];
            _checkRegularBucket(bucket);
            if (remainingDeficit == 0) continue;

            uint256 available = $.bucketAmount[token][bucket];
            uint256 loss = available < remainingDeficit ? available : remainingDeficit;
            if (loss == 0) continue;
            $.bucketAmount[token][bucket] = available - loss;
            remainingDeficit -= loss;
            emit BucketAllocationWrittenOff(token, bucket, loss, _msgSender());
        }

        if (remainingDeficit != 0) revert UncoveredBackingDeficit(token, remainingDeficit);
        $.bucketAllocated[token] = balance;
        emit BucketAllocatedRepaired(token, allocated, balance, _msgSender());
    }

    // Fixed durations; retain the existing constant getter names for ABI compatibility.
    uint256 public constant DEFAULT_UPGRADE_TIMELOCK = 2 days;
    uint256 public constant DEFAULT_UPGRADE_FINALIZE_WINDOW = 3 days;

    struct PendingUpgrade {
        address implementation;
        bytes data;
        uint256 validAfter;
        uint256 validBefore;
    }

    /// @custom:storage-location erc7201:kgold.storage.TreasuryUpgrade
    struct TreasuryUpgradeStorage {
        PendingUpgrade pending;
        // Deprecated timing fields retained to preserve the following storage slots.
        uint256 timelock;
        uint256 finalizeWindow;
        bool finalizing;
    }

    // keccak256(abi.encode(uint256(keccak256("kgold.storage.TreasuryUpgrade")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant TREASURY_UPGRADE_STORAGE =
        0x7e3d5be15a3c88917179919afef8148277f1cf7c6160eb886f95d3f492646500;

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
    event UpgradeFinalized(address indexed implementation, bytes32 indexed dataHash);
    event StagedUpgradeCancelled(address indexed implementation, bytes32 indexed dataHash);

    function pendingUpgrade() external view returns (PendingUpgrade memory) {
        return _getTreasuryUpgradeStorage().pending;
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
    /// @dev Before staging, verify that the migration omits nonReentrant: finalizeUpgrade holds
    /// the shared guard during its delegatecall. The migration must use reinitializer(n) with
    /// a fresh version, onlyRole(UPGRADER_ROLE), and require _getTreasuryUpgradeStorage().finalizing.
    /// The delegatecall preserves the upgrader as msg.sender. Use internal helpers instead of
    /// guarded public/external entry points; callbacks into those entry points remain blocked.
    /// No migration is provided here; add one in a future implementation when state changes require it.
    function stageNewImplementation(address newImplementation, bytes calldata data)
        external onlyProxy nonReentrant onlyRole(UPGRADER_ROLE)
    {
        TreasuryUpgradeStorage storage $ = _getTreasuryUpgradeStorage();
        if ($.finalizing) revert UpgradeAlreadyFinalizing();
        if ($.pending.implementation != address(0) && block.timestamp < $.pending.validBefore)
            revert UpgradeAlreadyStaged();
        if (
            newImplementation.code.length == 0 ||
            ERC1967Utils.getImplementation() == newImplementation
        ) revert InvalidImplementation(newImplementation);

        uint256 validAfter = block.timestamp + upgradeTimelock();
        uint256 validBefore = validAfter + upgradeFinalizeWindow();
        $.pending = PendingUpgrade({
            implementation: newImplementation,
            data: data,
            validAfter: validAfter,
            validBefore: validBefore
        });
        emit NewImplementationStaged(newImplementation, keccak256(data), validAfter, validBefore);
    }

    /// @notice Cancels a live staged upgrade or clears an expired one.
    function cancelStagedUpgrade() external onlyProxy nonReentrant onlyRole(CANCEL_UPGRADE_ROLE) {
        TreasuryUpgradeStorage storage $ = _getTreasuryUpgradeStorage();
        if ($.finalizing) revert UpgradeAlreadyFinalizing();
        address implementation = $.pending.implementation;
        if (implementation == address(0)) revert NoPendingUpgrade();
        bytes32 dataHash = keccak256($.pending.data);
        delete $.pending;
        emit StagedUpgradeCancelled(implementation, dataHash);
    }

    function finalizeUpgrade() external onlyProxy nonReentrant onlyRole(UPGRADER_ROLE) {
        TreasuryUpgradeStorage storage $ = _getTreasuryUpgradeStorage();
        if ($.finalizing) revert UpgradeAlreadyFinalizing();
        PendingUpgrade storage pending = $.pending;
        address implementation = pending.implementation;
        if (implementation == address(0)) revert NoPendingUpgrade();
        if (block.timestamp < pending.validAfter) revert UpgradeNotReady(pending.validAfter);
        if (block.timestamp >= pending.validBefore) revert UpgradeExpired(pending.validBefore);

        bytes memory data = pending.data;
        bytes32 dataHash = keccak256(data);
        $.finalizing = true;
        super.upgradeToAndCall(implementation, data);
        delete $.pending;
        $.finalizing = false;
        emit UpgradeFinalized(implementation, dataHash);
    }

    /// @dev Upgrades must use the staged flow; inherited direct UUPS upgrades are disabled.
    function upgradeToAndCall(address, bytes memory) public payable override onlyProxy {
        revert DirectUpgradeDisabled();
    }

    /// @dev finalizeUpgrade checks proxy context and upgrader authority before entering the UUPS upgrade path.
    function _authorizeUpgrade(address newImplementation)
        internal view override
    {
        TreasuryUpgradeStorage storage $ = _getTreasuryUpgradeStorage();
        if (!$.finalizing || $.pending.implementation != newImplementation)
            revert InvalidImplementation(newImplementation);
    }

    function _getTreasuryStorage() internal pure returns (TreasuryStorage storage $) {
        assembly {
            $.slot := TREASURY_STORAGE
        }
    }

    function _getTreasuryUpgradeStorage() internal pure returns (TreasuryUpgradeStorage storage $) {
        assembly {
            $.slot := TREASURY_UPGRADE_STORAGE
        }
    }

    function _checkRegularBucket(bytes32 bucket) internal pure {
        if (bucket == UNALLOCATED_BUCKET) revert InvalidBucket(bucket);
    }

    function _checkDepositPolicy(bytes32 bucket, address account) internal view {
        TreasuryStorage storage $ = _getTreasuryStorage();
        uint64 policyId = $.bucketPolicyIds[getBucketPolicyKey(bucket, DEPOSIT)];
        if (policyId == 0) return;
        if (
            !(
                _policyAuthorizes($.allBucketsPolicyId, account) ||
                _policyAuthorizes(policyId, account)
            )
        ) revert BucketAccessDenied(bucket, account);
    }

    function _checkWithdrawPolicy(bytes32 bucket, address account) internal view {
        TreasuryStorage storage $ = _getTreasuryStorage();
        uint64 policyId = $.bucketPolicyIds[getBucketPolicyKey(bucket, WITHDRAW)];
        if (
            !(
                _policyAuthorizes($.allBucketsPolicyId, account) ||
                _policyAuthorizes(policyId, account)
            )
        ) {
            if (policyId == 0) revert WithdrawPolicyRequired(bucket);
            revert BucketAccessDenied(bucket, account);
        }
    }

    function _policyAuthorizes(uint64 policyId, address account) internal view returns (bool) {
        // Zero grants no global override or withdrawal permission; deposits handle zero separately.
        if (policyId == 0) return false;
        // Unknown BLOCKLIST IDs authorize in the registry; never query them directly.
        if (!policyRegistry().policyExists(policyId)) return false;
        return isPolicyAuthorized(policyId, account);
    }

    function _backedBalance(
        address token
    ) internal view returns (uint256 balance) {
        if (token.code.length == 0) revert InvalidToken(token);
        balance = IERC20(token).balanceOf(address(this));
        uint256 allocated = bucketAllocated(token);
        if (balance < allocated)
            revert InsufficientBacking(token, balance, allocated);
    }

    function _requireBalance(
        address token,
        address account,
        uint256 expected
    ) internal view {
        uint256 actual = IERC20(token).balanceOf(account);
        if (actual != expected)
            revert UnexpectedTokenBalance(token, account, expected, actual);
    }

    function _debitBucket(
        address token,
        bytes32 bucket,
        uint256 amount
    ) internal {
        TreasuryStorage storage $ = _getTreasuryStorage();
        uint256 available = $.bucketAmount[token][bucket];
        if (amount > available)
            revert InsufficientBucketBalance(token, bucket, available, amount);
        $.bucketAmount[token][bucket] = available - amount;
    }
}
