// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {RoleRegistryClient} from "../roleRegistry/RoleRegistryClient.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    IERC20Permit
} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {
    ReentrancyGuard
} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ITreasury} from "./ITreasury.sol";
import {IPriceValidator} from "./IPriceValidator.sol";
import {ISignatureTransfer} from "./ISignatureTransfer.sol";

/// @notice Controller entry points for issuance, repurchase and redemption locks.
/// @dev Constructor-based deployment. The signed requiresBurn flag selects settlement with or
/// without burning the net input. Treasury must grant this Controller its manager role
/// and access to the quoted buckets. Redemption managers submit server-signed quotes and customer
/// permits to lock funds, then may refund or burn each lock. Relayed trades require customer authorization
/// of the full quote in addition to the server signature.
contract Controller is RoleRegistryClient, EIP712, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @notice Signs quotes after the server completes its off-chain customer checks.
    bytes32 public constant QUOTE_SIGNER_ROLE = keccak256("QUOTE_SIGNER_ROLE");
    /// @notice Configures daily Treasury withdrawal limits and price validators for each token pair.
    bytes32 public constant CONTROLLER_RISK_MANAGER_ROLE = keccak256("CONTROLLER_RISK_MANAGER_ROLE");
    /// @notice Executes signed redemption quotes using customer permits and finalizes locks by refund or burn.
    bytes32 public constant REDEEM_MANAGER_ROLE =
        keccak256("REDEEM_MANAGER_ROLE");

    // Conventional trade bucket identifiers. settleTrade uses the signed quote's buckets,
    // except for the reserved REDEEM_LOCK bucket. Treasury policies are configured separately.
    /// @notice Treasury bucket for already-minted KGLD inventory available for issue payouts.
    bytes32 public constant UNISSUED_KGLD = keccak256("UNISSUED_KGLD");
    /// @notice Treasury bucket for stablecoins received through issue, excluding fees.
    bytes32 public constant ISSUE_LIQUIDITY = keccak256("ISSUE_LIQUIDITY");
    /// @notice Treasury bucket for stablecoin fees collected through issue.
    bytes32 public constant ISSUE_FEE = keccak256("ISSUE_FEE");
    /// @notice Treasury bucket for repurchased KGLD awaiting burn, excluding fees.
    bytes32 public constant REPURCHASE_BURN_PENDING =
        keccak256("REPURCHASE_BURN_PENDING");
    /// @notice Treasury bucket for KGLD fees collected through repurchase.
    bytes32 public constant REPURCHASE_FEE = keccak256("REPURCHASE_FEE");
    /// @notice Treasury bucket for fees earned when physical redemption orders are burned.
    bytes32 public constant PHYSICAL_REDEEM_FEE =
        keccak256("PHYSICAL_REDEEM_FEE");
    /// @notice Holds redemption principal and refundable extra costs; unavailable to settleTrade.
    bytes32 public constant REDEEM_LOCK = keccak256("REDEEM_LOCK");

    bytes32 public constant TRADE_QUOTE_TYPEHASH =
        keccak256(
            "TradeQuote(bytes32 quoteId,bool requiresBurn,address owner,address tokenIn,address tokenOut,uint256 amountIn,uint256 amountOut,uint256 fee,uint256 price,uint256 deadline,bytes32 depositBucket,bytes32 withdrawBucket,bytes32 feeBucket)"
        );

    bytes32 public constant REDEEM_QUOTE_TYPEHASH =
        keccak256(
            "RedeemQuote(bytes32 quoteId,address owner,address token,uint256 principal,uint256 extraCost,uint256 deadline)"
        );

    /// @notice Uniswap's canonical Permit2 deployment. Never supplied by the caller.
    ISignatureTransfer public constant PERMIT2 =
        ISignatureTransfer(0x000000000022D473030F116dDEE9F6B43aC78BA3);

    /// @notice EIP-712 witness suffix for Permit2; dependencies are sorted by type name.
    string public constant PERMIT2_WITNESS_TYPE_STRING =
        "TradeQuote witness)TokenPermissions(address token,uint256 amount)TradeQuote(bytes32 quoteId,bool requiresBurn,address owner,address tokenIn,address tokenOut,uint256 amountIn,uint256 amountOut,uint256 fee,uint256 price,uint256 deadline,bytes32 depositBucket,bytes32 withdrawBucket,bytes32 feeBucket)";

    /// @dev Amounts use each token's base units. amountIn includes fee, denominated in tokenIn.
    /// amountOut is the exact tokenOut payout. The quote is valid through deadline, inclusive.
    /// price is signed but not passed to the validator, which checks the net input and output amounts.
    /// All bucket identifiers are signed. feeBucket is unused when fee is zero.
    struct TradeQuote {
        bytes32 quoteId;
        // Selects execution behavior independently of business labels such as issue/repurchase.
        bool requiresBurn;
        address owner;
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        uint256 amountOut;
        uint256 fee;
        uint256 price;
        uint256 deadline;
        bytes32 depositBucket;
        bytes32 withdrawBucket;
        bytes32 feeBucket;
    }

    /// @notice Server- and customer-signed terms for locking physical redemption funds.
    /// @dev An optional token permit approves principal + extraCost to this Controller.
    /// The quote is valid through deadline, inclusive. Both amounts use token's base units.
    struct RedeemQuote {
        bytes32 quoteId;
        address owner;
        address token;
        uint256 principal;
        uint256 extraCost;
        uint256 deadline;
    }

    /// @notice Lifecycle of a physical redemption lock; None is the unregistered default.
    enum RedeemStatus {
        None,
        Locked,
        Redeemed,
        Canceled
    }

    /// @notice Stored execution state of a redemption quote.
    /// @dev The quote ID is the redeemData mapping key. Both amounts use token's base units.
    /// Redeemed and Canceled are terminal states; only Locked quotes may be finalized.
    struct RedeemData {
        address owner;
        address token;
        RedeemStatus status;
        uint256 principal;
        uint256 extraCost;
    }

    /// @notice ERC-2612 signature approving Controller for the exact gross input or redemption total.
    /// @dev The token supplies the current nonce. A permit alone does not authorize quote details.
    struct PermitData {
        uint256 deadline;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    /// @notice Permit2 unordered nonce and expiry; token, amount and spender are derived by Controller.
    struct Permit2Data {
        uint256 nonce;
        uint256 deadline;
    }

    struct WithdrawUsage {
        uint256 dayStart;
        uint256 accumulatedAmount;
    }

    ITreasury public immutable treasury;
    // Directional pairs: tokenIn -> tokenOut. Zero skips price validation for that pair.
    mapping(address tokenIn => mapping(address tokenOut => address))
        public validationContract;

    /// @notice Quote IDs are single-use across trade and redemption entry points.
    mapping(bytes32 quoteId => bool) public consumed;
    /// @notice Physical redemption locks keyed by quote ID. Unregistered IDs return RedeemStatus.None.
    mapping(bytes32 quoteId => RedeemData) public redeemData;
    // Shared across all customers' trade payouts. Zero disables trades paying out that token; refunds are exempt.
    mapping(address token => uint256 limit) public withdrawLimit;
    mapping(address token => WithdrawUsage) public withdrawUsage;

    error InvalidContract(address target);
    error InvalidTradeQuote();
    error InvalidBurnMode(bool expected, bool actual);
    error InvalidTradeOwner(address owner, address caller);
    error QuoteExpired(uint256 deadline);
    error QuoteAlreadyConsumed(bytes32 quoteId);
    error InvalidQuoteSignature(address signer);
    error InvalidCustomerSignature(address owner);
    error PriceValidationFailed(address validator);
    error InvalidRedeemQuote();
    error InvalidRedeemStatus(
        bytes32 quoteId,
        RedeemStatus expected,
        RedeemStatus actual
    );
    error ReservedRedeemBucket();
    error WithdrawLimitExceeded(
        address token,
        uint256 limit,
        uint256 used,
        uint256 requested
    );
    error UnexpectedTokenBalance(
        address token,
        uint256 expected,
        uint256 actual
    );

    event WithdrawLimitUpdated(
        address indexed token,
        uint256 oldLimit,
        uint256 newLimit
    );
    event ValidationContractUpdated(
        address indexed tokenIn,
        address indexed tokenOut,
        address oldValidator,
        address newValidator
    );
    event TradeSettled(
        bytes32 indexed quoteId,
        address indexed owner,
        address indexed quoteSigner,
        TradeQuote quote
    );
    event RedeemLocked(
        bytes32 indexed quoteId,
        address indexed owner,
        address indexed quoteSigner,
        RedeemQuote quote,
        address manager
    );
    event RedeemLockCanceled(
        bytes32 indexed quoteId,
        address indexed owner,
        address indexed token,
        uint256 amountRefunded,
        address manager
    );
    event RedeemOrderBurned(
        bytes32 indexed quoteId,
        address indexed owner,
        address indexed token,
        uint256 principal,
        uint256 extraCost,
        address manager
    );

    constructor(
        address roleRegistry_,
        address treasury_
    ) RoleRegistryClient(roleRegistry_) EIP712("KGLD Controller", "1") {
        if (treasury_.code.length == 0) revert InvalidContract(treasury_);
        treasury = ITreasury(treasury_);
    }

    /// @notice Sets the maximum token units this Controller may pay out for trades per UTC day.
    /// @dev Changing a limit never resets that day's usage. Zero blocks trade payouts; refunds are exempt.
    function setWithdrawLimit(
        address token,
        uint256 newLimit
    ) external nonReentrant onlyRole(CONTROLLER_RISK_MANAGER_ROLE) {
        if (token.code.length == 0) revert InvalidContract(token);
        uint256 oldLimit = withdrawLimit[token];
        withdrawLimit[token] = newLimit;
        emit WithdrawLimitUpdated(token, oldLimit, newLimit);
    }

    /// @notice Sets the price validator for a directional token pair; zero disables validation.
    /// @dev Validators own the pricing formula and oracle settings. Pending quotes use the validator
    /// configured at execution time. Code existence is checked, not interface compatibility.
    function setValidationContract(
        address tokenIn,
        address tokenOut,
        address validator
    ) external nonReentrant onlyRole(CONTROLLER_RISK_MANAGER_ROLE) {
        if (validator != address(0) && validator.code.length == 0)
            revert InvalidContract(validator);
        address oldValidator = validationContract[tokenIn][tokenOut];
        validationContract[tokenIn][tokenOut] = validator;
        emit ValidationContractUpdated(
            tokenIn,
            tokenOut,
            oldValidator,
            validator
        );
    }

    /// @notice Returns today's aggregate withdrawal usage; stale stored usage is reported as zero.
    function withdrawnToday(address token) public view returns (uint256) {
        WithdrawUsage storage usage = withdrawUsage[token];
        return usage.dayStart == _dayStart() ? usage.accumulatedAmount : 0;
    }

    /// @notice EIP-712 digest signed by the quote signer (EOA or ERC-1271).
    function hashTradeQuote(
        TradeQuote calldata quote
    ) public view returns (bytes32) {
        // Every TradeQuote field is static, so ABI-encoding the tuple lays out its fields
        // inline after the type hash, exactly as required for this EIP-712 struct hash.
        return
            _hashTypedDataV4(
                keccak256(abi.encode(TRADE_QUOTE_TYPEHASH, quote))
            );
    }

    /// @notice EIP-712 digest signed by both the redemption quote signer and owner (EOA or ERC-1271).
    function hashRedeemQuote(
        RedeemQuote calldata quote
    ) public view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(abi.encode(REDEEM_QUOTE_TYPEHASH, quote))
            );
    }

    /// @notice Settles a quote with requiresBurn=false using the quoted tokens and Treasury buckets.
    /// @dev The caller must be the quote owner and must approve Controller for amountIn.
    /// The owner receives amountOut. All transfers, fees, consumption and limit usage are atomic.
    function settleTrade(
        TradeQuote calldata quote,
        address quoteSigner,
        bytes calldata quoteSignature
    ) external nonReentrant {
        if (quote.owner != _msgSender())
            revert InvalidTradeOwner(quote.owner, _msgSender());
        _checkTradeQuote(quote, quoteSigner, quoteSignature, false);
        _executeTrade(quote, quoteSigner);
    }

    /// @notice Relays a non-burning quote with the owner's EIP-712 signature and optional ERC-2612 approval.
    /// @dev Anyone may relay, but the full quote must be signed by both its owner and a quote signer.
    /// Permit failure is tolerated: transferFrom still requires sufficient allowance. quote.deadline
    /// controls trade expiry independently of permit validity. Payout always goes to the signed owner.
    function settleTradeWithPermit(
        TradeQuote calldata quote,
        address quoteSigner,
        bytes calldata quoteSignature,
        PermitData calldata permitData,
        bytes calldata customerSignature
    ) external nonReentrant {
        _checkTradeQuote(quote, quoteSigner, quoteSignature, false);
        _executeTradeWithPermit(quote, quoteSigner, permitData, customerSignature);
    }

    /// @notice Relays a non-burning quote with one customer Permit2 signature binding the full quote as witness.
    /// @dev The owner must first approve tokenIn to Uniswap Permit2. Controller is the signed spender;
    /// the input recipient is always Controller and the output recipient is always quote.owner.
    function settleTradeWithPermit2(
        TradeQuote calldata quote,
        address quoteSigner,
        bytes calldata quoteSignature,
        Permit2Data calldata permitData,
        bytes calldata permitSignature
    ) external nonReentrant {
        _checkTradeQuote(quote, quoteSigner, quoteSignature, false);
        if (address(PERMIT2).code.length == 0)
            revert InvalidContract(address(PERMIT2));
        _consumeTrade(quote);
        uint256 initialBalance = IERC20(quote.tokenIn).balanceOf(address(this));
        PERMIT2.permitWitnessTransferFrom(
            ISignatureTransfer.PermitTransferFrom({
                permitted: ISignatureTransfer.TokenPermissions({
                    token: quote.tokenIn,
                    amount: quote.amountIn
                }),
                nonce: permitData.nonce,
                deadline: permitData.deadline
            }),
            ISignatureTransfer.SignatureTransferDetails({
                to: address(this),
                requestedAmount: quote.amountIn
            }),
            quote.owner,
            keccak256(abi.encode(TRADE_QUOTE_TYPEHASH, quote)),
            PERMIT2_WITNESS_TYPE_STRING,
            permitSignature
        );
        _settleTrade(quote, quoteSigner, initialBalance);
    }

    /// @notice Settles a quote with requiresBurn=true and burns the net input in its deposit bucket.
    /// @dev Requires the owner caller; quote consumption is shared with the non-burning entry points.
    /// Treasury must have burn authority and Controller must have deposit-bucket withdrawal
    /// permission. If burning fails, the entire settlement reverts, including the payout.
    function settleTradeWithBurn(
        TradeQuote calldata quote,
        address quoteSigner,
        bytes calldata quoteSignature
    ) external nonReentrant {
        if (quote.owner != _msgSender())
            revert InvalidTradeOwner(quote.owner, _msgSender());
        _checkTradeQuote(quote, quoteSigner, quoteSignature, true);
        _executeTrade(quote, quoteSigner);
        _burnBucket(quote);
    }

    /// @notice Relays a quote with requiresBurn=true using customer consent and optional ERC-2612 approval.
    /// @dev Anyone may relay the server and customer signatures over the full quote. Permit failure
    /// is tolerated only if current allowance funds the trade. Burns amountIn - fee after settlement;
    /// any failure rolls back the permit, payout, fee, quote consumption and withdrawal usage.
    function settleTradeWithBurnWithPermit(
        TradeQuote calldata quote,
        address quoteSigner,
        bytes calldata quoteSignature,
        PermitData calldata permitData,
        bytes calldata customerSignature
    ) external nonReentrant {
        _checkTradeQuote(quote, quoteSigner, quoteSignature, true);
        _executeTradeWithPermit(quote, quoteSigner, permitData, customerSignature);
        _burnBucket(quote);
    }

    function _burnBucket(TradeQuote calldata quote) private {
        treasury.burnBucket(
            quote.tokenIn,
            quote.depositBucket,
            quote.amountIn - quote.fee
        );
    }

    function _checkTradeQuote(
        TradeQuote calldata quote,
        address quoteSigner,
        bytes calldata quoteSignature,
        bool expectedBurn
    ) private view {
        if (quote.requiresBurn != expectedBurn)
            revert InvalidBurnMode(expectedBurn, quote.requiresBurn);
        if (
            quote.owner == address(0) ||
            quote.owner == address(treasury) ||
            quote.tokenIn.code.length == 0 ||
            quote.tokenOut.code.length == 0 ||
            quote.tokenIn == quote.tokenOut ||
            quote.amountIn == 0 ||
            quote.amountOut == 0 ||
            quote.fee >= quote.amountIn ||
            quote.price == 0 ||
            quote.depositBucket == bytes32(0) ||
            quote.withdrawBucket == bytes32(0) ||
            quote.depositBucket == quote.withdrawBucket ||
            (quote.fee != 0 && quote.feeBucket == bytes32(0))
        ) revert InvalidTradeQuote();
        if (
            quote.depositBucket == REDEEM_LOCK ||
            quote.withdrawBucket == REDEEM_LOCK ||
            (quote.fee != 0 && quote.feeBucket == REDEEM_LOCK)
        ) revert ReservedRedeemBucket();
        if (block.timestamp > quote.deadline)
            revert QuoteExpired(quote.deadline);
        if (consumed[quote.quoteId]) revert QuoteAlreadyConsumed(quote.quoteId);
        _checkRole(QUOTE_SIGNER_ROLE, quoteSigner);
        if (
            !_isValidSignature(
                quoteSigner,
                hashTradeQuote(quote),
                quoteSignature
            )
        ) revert InvalidQuoteSignature(quoteSigner);
        _validatePrice(
            quote.tokenIn,
            quote.tokenOut,
            quote.amountIn - quote.fee,
            quote.amountOut
        );
    }

    function _executeTradeWithPermit(
        TradeQuote calldata quote,
        address quoteSigner,
        PermitData calldata permitData,
        bytes calldata customerSignature
    ) private {
        if (
            !_isValidSignature(
                quote.owner,
                hashTradeQuote(quote),
                customerSignature
            )
        ) revert InvalidCustomerSignature(quote.owner);
        _tryTradePermit(quote, permitData);
        _executeTrade(quote, quoteSigner);
    }

    function _executeTrade(
        TradeQuote calldata quote,
        address quoteSigner
    ) private {
        _consumeTrade(quote);
        IERC20 tokenIn = IERC20(quote.tokenIn);
        uint256 initialBalance = tokenIn.balanceOf(address(this));
        tokenIn.safeTransferFrom(quote.owner, address(this), quote.amountIn);
        _settleTrade(quote, quoteSigner, initialBalance);
    }

    function _consumeTrade(TradeQuote calldata quote) private {
        consumed[quote.quoteId] = true;
        _consumeWithdrawLimit(quote.tokenOut, quote.amountOut);
    }

    function _validatePrice(
        address tokenIn,
        address tokenOut,
        uint256 tokenInAmount,
        uint256 tokenOutAmount
    ) private view {
        address validator = validationContract[tokenIn][tokenOut];
        if (validator == address(0)) return;
        bool validated = IPriceValidator(validator).validatePrice(
            tokenInAmount,
            tokenOutAmount
        );
        if (!validated) revert PriceValidationFailed(validator);
    }

    // Same EOA/ERC-1271 validation as CommodityToken; avoids dependencies requiring a newer EVM target.
    function _isValidSignature(
        address signer,
        bytes32 digest,
        bytes calldata signature
    ) private view returns (bool) {
        if (signer == address(0)) return false;
        if (signer.code.length == 0) {
            (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecover(
                digest,
                signature
            );
            return err == ECDSA.RecoverError.NoError && recovered == signer;
        } else {
            (bool success, bytes memory result) = signer.staticcall(
                abi.encodeCall(IERC1271.isValidSignature, (digest, signature))
            );
            return
                success &&
                result.length >= 32 &&
                abi.decode(result, (bytes32)) ==
                bytes32(IERC1271.isValidSignature.selector);
        }
    }

    function _settleTrade(
        TradeQuote calldata quote,
        address quoteSigner,
        uint256 initialBalance
    ) private {
        IERC20 tokenIn = IERC20(quote.tokenIn);
        _requireBalance(tokenIn, initialBalance + quote.amountIn);

        // Approve only this settlement's gross amount, and clear any residual allowance afterwards.
        tokenIn.forceApprove(address(treasury), quote.amountIn);
        if (quote.fee != 0)
            treasury.deposit(quote.tokenIn, quote.feeBucket, quote.fee);
        treasury.depositAndWithdraw(
            quote.tokenIn,
            quote.depositBucket,
            quote.amountIn - quote.fee,
            quote.owner,
            quote.tokenOut,
            quote.withdrawBucket,
            quote.amountOut
        );
        tokenIn.forceApprove(address(treasury), 0);
        _requireBalance(tokenIn, initialBalance);
        emit TradeSettled(quote.quoteId, quote.owner, quoteSigner, quote);
    }

    function _consumeWithdrawLimit(address token, uint256 amount) internal {
        WithdrawUsage storage usage = withdrawUsage[token];
        uint256 dayStart = _dayStart();
        uint256 used = usage.dayStart == dayStart ? usage.accumulatedAmount : 0;
        uint256 limit = withdrawLimit[token];
        if (used > limit || amount > limit - used)
            revert WithdrawLimitExceeded(token, limit, used, amount);
        usage.dayStart = dayStart;
        usage.accumulatedAmount = used + amount;
    }

    function _dayStart() private view returns (uint256) {
        return block.timestamp - (block.timestamp % 1 days);
    }

    function _requireBalance(IERC20 token, uint256 expected) private view {
        uint256 actual = token.balanceOf(address(this));
        if (actual != expected)
            revert UnexpectedTokenBalance(address(token), expected, actual);
    }

    /// @notice Executes a server-signed redemption quote and locks its total in Treasury's REDEEM_LOCK bucket.
    /// @dev Both server and customer sign the entire quote, including the principal/extraCost split.
    /// After customer authorization, permit failures are allowed; transferFrom enforces allowance.
    /// Quote expiry is independent of permit expiry. Quote IDs must be nonzero and never reused.
    function redeemLock(
        RedeemQuote calldata quote,
        address quoteSigner,
        bytes calldata quoteSignature,
        PermitData calldata permitData,
        bytes calldata customerSignature
    ) external nonReentrant onlyRole(REDEEM_MANAGER_ROLE) {
        _checkRedeemQuote(quote, quoteSigner, quoteSignature);
        if (
            !_isValidSignature(
                quote.owner,
                hashRedeemQuote(quote),
                customerSignature
            )
        ) revert InvalidCustomerSignature(quote.owner);

        consumed[quote.quoteId] = true;
        redeemData[quote.quoteId] = RedeemData({
            owner: quote.owner,
            token: quote.token,
            status: RedeemStatus.Locked,
            principal: quote.principal,
            extraCost: quote.extraCost
        });

        uint256 amount = quote.principal + quote.extraCost;
        _tryRedeemPermit(quote.owner, quote.token, amount, permitData);
        IERC20 asset = IERC20(quote.token);
        uint256 initialBalance = asset.balanceOf(address(this));
        asset.safeTransferFrom(quote.owner, address(this), amount);
        _requireBalance(asset, initialBalance + amount);
        asset.forceApprove(address(treasury), amount);
        treasury.deposit(quote.token, REDEEM_LOCK, amount);
        asset.forceApprove(address(treasury), 0);
        _requireBalance(asset, initialBalance);

        emit RedeemLocked(
            quote.quoteId,
            quote.owner,
            quoteSigner,
            quote,
            _msgSender()
        );
    }

    function _checkRedeemQuote(
        RedeemQuote calldata quote,
        address quoteSigner,
        bytes calldata quoteSignature
    ) private view {
        if (
            quote.quoteId == bytes32(0) ||
            quote.owner == address(0) ||
            quote.owner == address(this) ||
            quote.owner == address(treasury) ||
            quote.principal == 0 ||
            quote.principal > type(uint256).max - quote.extraCost
        ) revert InvalidRedeemQuote();
        if (quote.token.code.length == 0) revert InvalidContract(quote.token);
        if (block.timestamp > quote.deadline)
            revert QuoteExpired(quote.deadline);
        if (consumed[quote.quoteId]) revert QuoteAlreadyConsumed(quote.quoteId);
        _checkRedeemStatus(quote.quoteId, RedeemStatus.None);
        _checkRole(QUOTE_SIGNER_ROLE, quoteSigner);
        if (
            !_isValidSignature(
                quoteSigner,
                hashRedeemQuote(quote),
                quoteSignature
            )
        ) revert InvalidQuoteSignature(quoteSigner);
    }

    /// @dev Only called after validating the customer's full trade signature. A failed permit
    /// does not revoke that trade authorization; safeTransferFrom enforces the current allowance.
    function _tryTradePermit(
        TradeQuote calldata quote,
        PermitData calldata permitData
    ) private {
        try IERC20Permit(quote.tokenIn).permit(
            quote.owner,
            address(this),
            quote.amountIn,
            permitData.deadline,
            permitData.v,
            permitData.r,
            permitData.s
        ) {} catch {}
    }

    /// @dev Customer quote authorization is checked first; transferFrom enforces current allowance.
    function _tryRedeemPermit(
        address owner,
        address token,
        uint256 amount,
        PermitData calldata permitData
    ) private {
        try IERC20Permit(token).permit(
            owner,
            address(this),
            amount,
            permitData.deadline,
            permitData.v,
            permitData.r,
            permitData.s
        ) {} catch {}
    }

    /// @notice Refunds a locked quote's entire principal and extra cost to its recorded owner.
    /// @dev Returning locked funds does not consume the daily trade withdrawal limit.
    function cancelRedeemLock(
        bytes32 quoteId
    ) external nonReentrant onlyRole(REDEEM_MANAGER_ROLE) {
        _checkRedeemStatus(quoteId, RedeemStatus.Locked);
        RedeemData storage data = redeemData[quoteId];
        data.status = RedeemStatus.Canceled;
        uint256 amount = data.principal + data.extraCost;
        treasury.withdraw(data.owner, data.token, REDEEM_LOCK, amount);
        emit RedeemLockCanceled(
            quoteId,
            data.owner,
            data.token,
            amount,
            _msgSender()
        );
    }

    /// @notice Burns a locked quote's principal and allocates its extra cost to PHYSICAL_REDEEM_FEE.
    /// @dev The token must support Treasury's burn(uint256) call. Bucket movement and burning
    /// do not consume the transfer withdrawal limit. Any failure restores the Locked state.
    function burnRedeemOrder(
        bytes32 quoteId
    ) external nonReentrant onlyRole(REDEEM_MANAGER_ROLE) {
        _checkRedeemStatus(quoteId, RedeemStatus.Locked);
        RedeemData storage data = redeemData[quoteId];
        data.status = RedeemStatus.Redeemed;
        treasury.burnBucket(data.token, REDEEM_LOCK, data.principal);
        if (data.extraCost != 0) {
            treasury.bucketTransfer(
                data.token,
                REDEEM_LOCK,
                PHYSICAL_REDEEM_FEE,
                data.extraCost
            );
        }
        emit RedeemOrderBurned(
            quoteId,
            data.owner,
            data.token,
            data.principal,
            data.extraCost,
            _msgSender()
        );
    }

    function _checkRedeemStatus(
        bytes32 quoteId,
        RedeemStatus expected
    ) private view {
        RedeemStatus actual = redeemData[quoteId].status;
        if (actual != expected)
            revert InvalidRedeemStatus(quoteId, expected, actual);
    }
}
