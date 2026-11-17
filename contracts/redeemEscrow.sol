// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {RoleRegistryClient} from "./roleRegistry/RoleRegistryClient.sol";
import {IPolicyRegistry} from "./policyRegistry/IPolicyRegistry.sol";

/// @dev CommodityToken v2's EOA/ERC-1271 ERC-3009 extension and role-protected burn API.
interface IRedeemEscrowToken is IERC20 {
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes calldata signature
    ) external;

    function authorizationState(address authorizer, bytes32 nonce) external view returns (bool);

    function burn(uint256 amount) external;

    function policyRegistry() external view returns (IPolicyRegistry);
    function policyId(bytes32 scope) external view returns (uint64);
    function hasRole(bytes32 role, address account) external view returns (bool);
}

/// @title Customer-confirmed physical redemption escrow for a fixed KGLD token.
/// @notice Deposited and unswept force-terminated orders can be refunded if token transfer succeeds.
/// Confirmation requires a Locked order and the owner's valid EIP-712 signature,
/// and burns the entire order amount.
/// Only a redeem manager other than the owner may confirm, after the off-chain KYT workflow.
/// Confirmation requires owner authorization for sender/receiver/executor and exclusion from forced-source.
/// @dev Constructor-based and non-upgradeable. A manager may force-terminate sanctioned owners' Locked orders;
/// Force-terminated funds remain allocated until cancellation or risk-manager attestation of an external sweep.
/// The token must grant this escrow BURNER_ROLE and the applicable transfer policies.
/// Locks have no expiration. Only signature validity windows expire. No delivery verification.
/// Token-level administrators and the external role registry retain their existing powers.
contract RedeemEscrow is RoleRegistryClient, EIP712, ReentrancyGuard {
    using SafeERC20 for IERC20;

    bytes32 public constant REDEEM_MANAGER_ROLE = keccak256("REDEEM_MANAGER_ROLE");
    /// @notice Checked on the token; escrow-local membership does not authorize sweep accounting.
    bytes32 public constant TOKEN_RISK_MANAGER_ROLE = keccak256("TOKEN_RISK_MANAGER_ROLE");
    bytes32 public constant TRANSFER_SENDER_POLICY = keccak256("TRANSFER_SENDER_POLICY");
    bytes32 public constant TRANSFER_RECEIVER_POLICY = keccak256("TRANSFER_RECEIVER_POLICY");
    bytes32 public constant TRANSFER_EXECUTOR_POLICY = keccak256("TRANSFER_EXECUTOR_POLICY");
    bytes32 public constant FORCED_TRANSFER_SOURCE_POLICY = keccak256("FORCED_TRANSFER_SOURCE_POLICY");
    bytes32 public constant DEPOSIT_AUTHORIZATION_NONCE_TAG = keccak256("KGLD_REDEEM_DEPOSIT_V1");
    bytes32 public constant CONFIRM_REDEEM_ORDER_TYPEHASH = keccak256(
        "ConfirmRedeemOrder(bytes32 quoteId,address owner,uint256 amount,uint256 lockNonce,uint256 deadline)"
    );

    enum OrderStatus {
        None,
        Deposited,
        Locked,
        Confirmed,
        Canceled,
        ForcedTerminated
    }

    struct RedeemOrder {
        address owner;
        uint256 amount;
        OrderStatus status;
        uint256 lockNonce;
        bool swept;
    }

    IRedeemEscrowToken public immutable token;
    /// @notice Stored order data. Confirmation eligibility has a separate view function.
    /// @dev Terminal orders are retained, preventing reuse of quoteId.
    mapping(bytes32 quoteId => RedeemOrder) public orders;
    /// @notice Amount allocated to Deposited, Locked and unswept ForcedTerminated orders.
    /// @dev Excludes unsolicited transfers. All totals describe stored states, not elapsed time alone.
    uint256 public totalEscrowed;
    /// @notice Current amount allocated to Deposited orders, not cumulative deposits.
    uint256 public totalDeposited;
    /// @notice Amount in Locked orders until they are settled, terminated or unlocked.
    /// @dev Terminated outstanding = totalEscrowed - totalDeposited - totalLocked.
    uint256 public totalLocked;

    error InvalidToken(address token);
    error InvalidQuoteId();
    error InvalidOwner(address owner);
    error InvalidAmount();
    error InvalidPolicyRegistry(address registry);
    error PolicyAccessDenied(address registry, uint64 policyId, address account);
    error InvalidOrderStatus(bytes32 quoteId, OrderStatus current, OrderStatus required);
    error OrderAlreadySwept(bytes32 quoteId);
    error ConfirmationExpired(uint256 deadline);
    error InvalidConfirmationSignature();
    error OwnerCannotConfirm(address owner);
    error OwnerNotSanctioned(address owner, bytes32 scope);
    error InvalidAuthorizationWindow(uint256 validAfter, uint256 validBefore);
    error InvalidAuthorizationState(address owner, bytes32 nonce);
    error InsufficientBacking(uint256 balance, uint256 required);
    error UnexpectedBalance(address account, uint256 expected, uint256 actual);
    error UnexpectedTotalSupply(uint256 expected, uint256 actual);

    event RedeemDeposited(bytes32 indexed quoteId, address indexed owner, uint256 amount);
    event RedeemOrderLocked(bytes32 indexed quoteId, address indexed manager, uint256 lockNonce);
    event RedeemOrderUnlocked(bytes32 indexed quoteId, address indexed manager, uint256 lockNonce);
    event RedeemOrderCanceled(
        bytes32 indexed quoteId,
        address indexed owner,
        address indexed caller,
        uint256 amount
    );
    event RedeemOrderConfirmed(
        bytes32 indexed quoteId,
        address indexed owner,
        address indexed caller,
        uint256 amount,
        uint256 lockNonce
    );
    event RedeemOrderForceTerminated(
        bytes32 indexed quoteId,
        address indexed owner,
        address indexed manager,
        uint256 amount,
        uint256 lockNonce
    );
    event RedeemOrderSwept(bytes32 indexed quoteId, address indexed owner, address indexed caller, uint256 amount);
    constructor(address roleRegistry_, address token_)
        RoleRegistryClient(roleRegistry_)
        EIP712("KGLD Redeem Escrow", "1")
    {
        if (token_.code.length == 0) revert InvalidToken(token_);
        token = IRedeemEscrowToken(token_);
    }

    /// @notice Non-sequential ERC-3009 nonce binding the deposit purpose, chain, escrow and quoteId.
    /// @dev Clients must derive this same nonce before signing ReceiveWithAuthorization.
    /// The token domain binds the token address; from/to/value/time bounds are signed fields.
    function depositAuthorizationNonce(bytes32 quoteId) public view returns (bytes32) {
        if (quoteId == bytes32(0)) revert InvalidQuoteId();
        return keccak256(abi.encode(DEPOSIT_AUTHORIZATION_NONCE_TAG, block.chainid, address(this), quoteId));
    }

    /// @notice A manager deposits exactly amount using the owner's quote-bound ERC-3009 signature.
    /// @dev The nonce is derived here, never accepted from the manager. receiveWithAuthorization
    /// requires the caller to be the recipient, preventing standalone execution of the transfer
    /// outside this deposit flow. No approval or transferFrom is used. Time bounds restrict the
    /// deposit only, not subsequent locking or confirmation. Canceled authorizations cannot be reused.
    function depositWithAuthorization(
        bytes32 quoteId,
        uint256 amount,
        address owner,
        uint256 validAfter,
        uint256 validBefore,
        bytes calldata authorizationSignature
    ) external nonReentrant onlyRole(REDEEM_MANAGER_ROLE) {
        if (quoteId == bytes32(0)) revert InvalidQuoteId();
        if (owner == address(0) || owner == address(this) || owner == address(token)) {
            revert InvalidOwner(owner);
        }
        if (amount == 0) revert InvalidAmount();
        RedeemOrder storage order = orders[quoteId];
        _requireStatus(quoteId, order, OrderStatus.None);
        if (block.timestamp <= validAfter || block.timestamp >= validBefore) {
            revert InvalidAuthorizationWindow(validAfter, validBefore);
        }
        bytes32 nonce = depositAuthorizationNonce(quoteId);
        if (token.authorizationState(owner, nonce)) revert InvalidAuthorizationState(owner, nonce);

        uint256 balanceBefore = _backedBalance();
        order.owner = owner;
        order.amount = amount;
        order.status = OrderStatus.Deposited;
        totalDeposited += amount;
        totalEscrowed += amount;

        token.receiveWithAuthorization(owner, address(this), amount, validAfter, validBefore, nonce, authorizationSignature);
        if (!token.authorizationState(owner, nonce)) revert InvalidAuthorizationState(owner, nonce);
        _requireBalance(address(this), balanceBefore + amount);

        emit RedeemDeposited(quoteId, owner, amount);
    }

    /// @notice Starts processing a deposited order without an expiration period.
    /// @dev Each lock changes the confirmation nonce, invalidating earlier-round signatures.
    function lockOrder(bytes32 quoteId) external nonReentrant onlyRole(REDEEM_MANAGER_ROLE) {
        RedeemOrder storage order = orders[quoteId];
        _requireStatus(quoteId, order, OrderStatus.Deposited);
        order.lockNonce += 1;
        order.status = OrderStatus.Locked;
        totalDeposited -= order.amount;
        totalLocked += order.amount;
        emit RedeemOrderLocked(quoteId, _msgSender(), order.lockNonce);
    }

    /// @notice Returns a Locked order to Deposited without moving tokens.
    function unlockRedeemOrder(bytes32 quoteId) external nonReentrant onlyRole(REDEEM_MANAGER_ROLE) {
        RedeemOrder storage order = orders[quoteId];
        _requireStatus(quoteId, order, OrderStatus.Locked);
        totalLocked -= order.amount;
        order.status = OrderStatus.Deposited;
        totalDeposited += order.amount;
        emit RedeemOrderUnlocked(quoteId, _msgSender(), order.lockNonce);
    }

    /// @notice Stored lifecycle status. Time passing alone never changes it; unknown quoteIds return None.
    function getOrderStatus(bytes32 quoteId) external view returns (OrderStatus) {
        return orders[quoteId].status;
    }

    /// @notice Lifecycle eligibility only; caller access, owner policy, signature and burn checks run on confirmation.
    function canConfirmRedeemOrder(bytes32 quoteId) external view returns (bool) {
        RedeemOrder storage order = orders[quoteId];
        return order.status == OrderStatus.Locked;
    }

    /// @notice Ends redemption and releases the order lock without moving or burning tokens.
    /// @dev Owner must be denied by sender/receiver/executor policies and allowed by forced-source policy.
    /// All four current token policies must exist and be nonzero. Funds remain allocated until cancellation or sweep accounting.
    function forceTerminateOrder(bytes32 quoteId) external nonReentrant onlyRole(REDEEM_MANAGER_ROLE) {
        RedeemOrder storage order = orders[quoteId];
        _requireStatus(quoteId, order, OrderStatus.Locked);
        _checkTerminationOwnerPolicies(order.owner);
        order.status = OrderStatus.ForcedTerminated;
        totalLocked -= order.amount;
        emit RedeemOrderForceTerminated(quoteId, order.owner, _msgSender(), order.amount, order.lockNonce);
    }

    function _checkTerminationOwnerPolicies(address owner) private view {
        IPolicyRegistry registry = token.policyRegistry();
        if (address(registry).code.length == 0) revert InvalidPolicyRegistry(address(registry));
        bytes32[4] memory scopes = [
            TRANSFER_SENDER_POLICY, TRANSFER_RECEIVER_POLICY,
            TRANSFER_EXECUTOR_POLICY, FORCED_TRANSFER_SOURCE_POLICY
        ];
        for (uint256 i = 0; i < scopes.length; ++i) {
            uint64 id = token.policyId(scopes[i]);
            // Missing policies must never count as evidence of sanctions, even if they deny by default.
            if (id == 0 || !registry.policyExists(id)) revert OwnerNotSanctioned(owner, scopes[i]);
            bool expectedAuthorization = scopes[i] == FORCED_TRANSFER_SOURCE_POLICY;
            if (registry.isAuthorized(id, owner) != expectedAuthorization) {
                revert OwnerNotSanctioned(owner, scopes[i]);
            }
        }
    }

    /// @notice Records full external seizure of a ForcedTerminated order; does not move or burn tokens.
    /// @dev Checks the token's effective risk-manager role, not an escrow-local role with the same name.
    /// The caller attests that the full amount was seized externally. No transfer proof is verified here.
    /// Do not enforce backing: external seizures may leave multiple orders awaiting reconciliation.
    /// Status stays ForcedTerminated; swept permanently prevents another accounting entry or refund.
    function markAsSwept(bytes32 quoteId) external nonReentrant {
        if (!token.hasRole(TOKEN_RISK_MANAGER_ROLE, _msgSender())) {
            revert AccessControlUnauthorizedAccount(_msgSender(), TOKEN_RISK_MANAGER_ROLE);
        }
        RedeemOrder storage order = orders[quoteId];
        _requireStatus(quoteId, order, OrderStatus.ForcedTerminated);
        if (order.swept) revert OrderAlreadySwept(quoteId);
        order.swept = true;
        totalEscrowed -= order.amount;
        emit RedeemOrderSwept(quoteId, order.owner, _msgSender(), order.amount);
    }

    /// @notice The owner or a manager can refund Deposited or unswept ForcedTerminated orders in full.
    /// @dev Locked orders must first be unlocked or force-terminated. Token transfer enforces refund eligibility;
    /// no separate owner policy check or partial-deduction policy is implemented here.
    /// The recipient is always the stored owner. A failed refund rolls back status and totals.
    function cancelRedeemOrder(bytes32 quoteId) external nonReentrant {
        RedeemOrder storage order = orders[quoteId];
        bool wasTerminated = order.status == OrderStatus.ForcedTerminated;
        if (!wasTerminated) _requireStatus(quoteId, order, OrderStatus.Deposited);
        if (order.swept) revert OrderAlreadySwept(quoteId);
        if (_msgSender() != order.owner) _checkRole(REDEEM_MANAGER_ROLE, _msgSender());

        uint256 balanceBefore = _backedBalance();
        uint256 ownerBalanceBefore = token.balanceOf(order.owner);
        order.status = OrderStatus.Canceled;
        if (!wasTerminated) totalDeposited -= order.amount;
        totalEscrowed -= order.amount;

        IERC20(address(token)).safeTransfer(order.owner, order.amount);
        _requireBalance(address(this), balanceBefore - order.amount);
        _requireBalance(order.owner, ownerBalanceBefore + order.amount);

        emit RedeemOrderCanceled(quoteId, order.owner, _msgSender(), order.amount);
    }

    /// @notice A redeem manager other than the owner relays the owner's EIP-712 confirmation.
    /// @dev Supports EOA and ERC-1271 owners. The digest binds the current lock nonce, order,
    /// amount, owner, deadline, chain and escrow address. Terminal states prevent replay.
    /// KYT is performed off-chain by the manager. All four owner sanctions policies are checked
    /// separately from the escrow's burn policies. Any denial reverts without termination.
    function confirmRedeemOrderWithSignature(
        bytes32 quoteId,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant onlyRole(REDEEM_MANAGER_ROLE) {
        RedeemOrder storage order = orders[quoteId];
        _requireStatus(quoteId, order, OrderStatus.Locked);
        if (_msgSender() == order.owner) revert OwnerCannotConfirm(order.owner);
        if (block.timestamp > deadline) revert ConfirmationExpired(deadline);
        if (!SignatureChecker.isValidSignatureNow(order.owner, _confirmationDigest(quoteId, order, deadline), signature)) {
            revert InvalidConfirmationSignature();
        }
        _checkConfirmationOwnerPolicies(order.owner);
        _confirmRedeemOrder(quoteId, order);
    }

    function _checkConfirmationOwnerPolicies(address owner) private view {
        IPolicyRegistry registry = token.policyRegistry();
        if (address(registry).code.length == 0) revert InvalidPolicyRegistry(address(registry));
        bytes32[4] memory scopes = [
            TRANSFER_SENDER_POLICY, TRANSFER_RECEIVER_POLICY,
            TRANSFER_EXECUTOR_POLICY, FORCED_TRANSFER_SOURCE_POLICY
        ];
        for (uint256 i = 0; i < scopes.length; ++i) {
            uint64 id = token.policyId(scopes[i]);
            // Unknown policies must never permit confirmation, including unknown allowlists
            // that would deny forced-source authorization by default.
            if (!registry.policyExists(id)) revert PolicyAccessDenied(address(registry), id, owner);
            bool forcedSource = scopes[i] == FORCED_TRANSFER_SOURCE_POLICY;
            // Match token semantics: zero allows ordinary transfers but disables forced transfers.
            if (forcedSource && id == 0) continue;
            if (registry.isAuthorized(id, owner) != !forcedSource) {
                revert PolicyAccessDenied(address(registry), id, owner);
            }
        }
    }

    /// @notice Returns the EIP-712 digest for a Locked order with the supplied signature deadline.
    function hashConfirmRedeemOrder(bytes32 quoteId, uint256 deadline) external view returns (bytes32) {
        RedeemOrder storage order = orders[quoteId];
        _requireStatus(quoteId, order, OrderStatus.Locked);
        return _confirmationDigest(quoteId, order, deadline);
    }

    function _confirmationDigest(
        bytes32 quoteId,
        RedeemOrder storage order,
        uint256 deadline
    ) private view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(
            CONFIRM_REDEEM_ORDER_TYPEHASH,
            quoteId,
            order.owner,
            order.amount,
            order.lockNonce,
            deadline
        )));
    }

    function _confirmRedeemOrder(bytes32 quoteId, RedeemOrder storage order) private {
        uint256 balanceBefore = _backedBalance();
        uint256 supplyBefore = token.totalSupply();
        order.status = OrderStatus.Confirmed;
        totalLocked -= order.amount;
        totalEscrowed -= order.amount;

        token.burn(order.amount);
        _requireBalance(address(this), balanceBefore - order.amount);
        uint256 supplyAfter = token.totalSupply();
        if (supplyAfter != supplyBefore - order.amount) {
            revert UnexpectedTotalSupply(supplyBefore - order.amount, supplyAfter);
        }

        emit RedeemOrderConfirmed(quoteId, order.owner, _msgSender(), order.amount, order.lockNonce);
    }

    function _requireStatus(bytes32 quoteId, RedeemOrder storage order, OrderStatus required) private view {
        if (order.status != required) revert InvalidOrderStatus(quoteId, order.status, required);
    }

    function _backedBalance() private view returns (uint256 balance) {
        balance = token.balanceOf(address(this));
        if (balance < totalEscrowed) revert InsufficientBacking(balance, totalEscrowed);
    }

    function _requireBalance(address account, uint256 expected) private view {
        uint256 actual = token.balanceOf(account);
        if (actual != expected) revert UnexpectedBalance(account, expected, actual);
    }
}
