// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {
    IERC20Metadata
} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {
    IERC20Permit
} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

import {
    ReentrancyGuard
} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

contract CommodityTokenIssuer is AccessControl, ReentrancyGuard {
    using SafeERC20 for IERC20;

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);

        _setRoleAdmin(WHITELISTED_ROLE, OPERATION_MANAGER_ROLE);
    }

    // ====================
    // Pair availability
    // ====================
    bool public areAllPairsAvailable = false;

    mapping(bytes32 => bool) public availablePairs;

    event AreAllPairsAvailableChanged(bool status);
    event AvailablePairChanged(
        address indexed taIn,
        address indexed taOut,
        bool status
    );

    function setAreAllPairsAvailable(
        bool _status
    ) external onlyRole(OPERATION_MANAGER_ROLE) {
        areAllPairsAvailable = _status;

        emit AreAllPairsAvailableChanged(_status);
    }
    function setAvailablePair(
        address _taIn,
        address _taOut,
        bool _status
    ) external onlyRole(OPERATION_MANAGER_ROLE) {
        bytes32 pairKey = keccak256(abi.encodePacked(_taIn, _taOut));
        availablePairs[pairKey] = _status;

        emit AvailablePairChanged(_taIn, _taOut, _status);
    }

    function isAvailablePair(
        address _taIn,
        address _taOut
    ) public view returns (bool) {
        if (_taIn == _taOut) {
            return false;
        }
        if (areAllPairsAvailable) {
            return true;
        }
        bytes32 pairKey = keccak256(abi.encodePacked(_taIn, _taOut));
        return availablePairs[pairKey];
    }

    error PairNotAvailable(address tokenAddressIn, address tokenAddressOut);
    modifier onlyAvailablePair(address _taIn, address _taOut) {
        if (!isAvailablePair(_taIn, _taOut))
            revert PairNotAvailable(_taIn, _taOut);
        _;
    }

    // ====================
    // Roles
    // ====================
    // 0x261b87b2321a08d52f3b3ee0167bc0ecb9d54938405960f6cfb55fe47cab3c0e;
    bytes32 public constant OPERATION_MANAGER_ROLE =
        keccak256("OPERATION_MANAGER_ROLE");

    // 0x8429d542926e6695b59ac6fbdcd9b37e8b1aeb757afab06ab60b1bb5878c3b49;
    bytes32 public constant WHITELISTED_ROLE = keccak256("WHITELISTED_ROLE");

    // 0xb1fadd3142ab2ad7f1337ea4d97112bcc8337fc11ce5b20cb04ad038adf99819;
    bytes32 public constant ASSET_MANAGER_ROLE =
        keccak256("ASSET_MANAGER_ROLE");

    uint256 public constant BIAS_POINT_DENOMINATOR = 10000;

    // ====================
    // Fee management
    // ====================
    uint256 public feeBps = 0; // in basis points (bps), ex) 1% = 100 bps
    mapping(address => uint256) public cumulatedFees;

    error FeeTooHigh(uint256 attemptedFeeBps);
    event FeeBpsChanged(uint256 oldFeeBps, uint256 newFeeBps);

    // @notice FeeBps should be less than 100%
    function setFeeBps(
        uint256 _newFeeBps
    ) external onlyRole(ASSET_MANAGER_ROLE) {
        if (_newFeeBps >= BIAS_POINT_DENOMINATOR) {
            revert FeeTooHigh(_newFeeBps);
        }
        uint256 oldFeeBps = feeBps;
        feeBps = _newFeeBps;
        emit FeeBpsChanged(oldFeeBps, _newFeeBps);
    }

    // ====================
    // Whitelist Management
    // ====================
    bool public isWhitelistActive = true;

    event WhitelistStatusChanged(bool status);

    // @notice If the status is false, the whitelist check will be skipped and anyone can call the issue function. If the status is true, only whitelisted addresses can be the recipient.
    function setWhitelistStatus(
        bool _status
    ) external onlyRole(OPERATION_MANAGER_ROLE) {
        if (isWhitelistActive != _status) {
            isWhitelistActive = _status;
            emit WhitelistStatusChanged(_status);
        } else {
            revert NothingChanged();
        }
    }

    event WhitelistSet(address indexed walletAddress, bool status);
    function setWhitelistAddress(
        address _addr,
        bool _status
    ) external onlyRole(OPERATION_MANAGER_ROLE) {
        if (hasRole(WHITELISTED_ROLE, _addr) != _status) {
            if (_status) {
                grantRole(WHITELISTED_ROLE, _addr); // Only OPERATION_MANAGER_ROLE can call this function, as it's the admin of WHITELISTED_ROLE
            } else {
                revokeRole(WHITELISTED_ROLE, _addr); // Only OPERATION_MANAGER_ROLE can call this function, as it's the admin of WHITELISTED_ROLE
            }
            emit WhitelistSet(_addr, _status);
        } else {
            revert NothingChanged();
        }
    }

    error NotWhitelisted(address walletAddress);
    function checkIsWhitelisted(address walletAddress) internal view {
        if (isWhitelistActive && !hasRole(WHITELISTED_ROLE, walletAddress)) {
            revert NotWhitelisted(walletAddress);
        }
    }

    // ====================
    // Pause Management
    // ====================
    bool public isPaused = false;
    event PauseStatusChanged(bool status);
    function setPauseStatus(
        bool _status
    ) external onlyRole(OPERATION_MANAGER_ROLE) {
        if (isPaused != _status) {
            isPaused = _status;
            emit PauseStatusChanged(_status);
        } else {
            revert NothingChanged();
        }
    }

    error ContractPaused();
    modifier whenNotPaused() {
        if (isPaused) {
            revert ContractPaused();
        }
        _;
    }

    // ====================
    // Issue Logic
    // ====================
    struct QuoteData {
        uint256 amtIn;
        uint256 amtOut;
        uint256 fee;
        uint256 exRateIn;
        uint256 exRateOut;
    }

    error InvalidExchangeRate();
    // @param _amtOut should apply retainingDecimals truncation and fee deduction. : User should receive "_amtOut" or more, but not less.
    function getAmountIn(
        address _taIn,
        address _taOut,
        uint256 _amtOut, // Desired token amount to receive, after fee deduction
        uint256 _exRateIn, // Exchange rate for the input token, should be 8-decimal value.
        uint256 _exRateOut, // Exchange rate for the output token, should be 8-decimal value.
        uint256 _retainingDecimals
    ) public view returns (QuoteData memory data) {
        if (_exRateIn == 0 || _exRateOut == 0) {
            revert InvalidExchangeRate();
        }
        if (_amtOut == 0) {
            revert InvalidAmountOut();
        }

        uint256 dIn = uint256(IERC20Metadata(_taIn).decimals());
        uint256 dOut = uint256(IERC20Metadata(_taOut).decimals());

        uint256 step = 10 **
            (dOut > _retainingDecimals ? (dOut - _retainingDecimals) : 0);
        if (_amtOut % step != 0) {
            revert InvalidAmountOut();
        }

        uint256 net = Math.mulDiv(
            Math.mulDiv(_amtOut, 10 ** dIn, 1),
            _exRateOut,
            _exRateIn * (10 ** dOut),
            Math.Rounding.Ceil
        );

        uint256 amtIn = Math.mulDiv(
            net,
            BIAS_POINT_DENOMINATOR + feeBps,
            BIAS_POINT_DENOMINATOR,
            Math.Rounding.Ceil
        );

        QuoteData memory q = getAmountOut(
            _taIn,
            _taOut,
            amtIn,
            _exRateIn,
            _exRateOut,
            _retainingDecimals
        );

        return q;
    }

    function getAmountOut(
        address _taIn,
        address _taOut,
        uint256 _amtIn, // Token amount to pay, before fee deduction
        uint256 _exRateIn, // Exchange rate for the input token, should be 8-decimal value.
        uint256 _exRateOut, // Exchange rate for the output token, should be 8-decimal value.
        uint256 _retainingDecimals
    ) public view returns (QuoteData memory) {
        if (_exRateIn == 0 || _exRateOut == 0) {
            revert InvalidExchangeRate();
        }

        uint256 net = Math.mulDiv(
            _amtIn,
            BIAS_POINT_DENOMINATOR,
            BIAS_POINT_DENOMINATOR + feeBps
        );
        uint256 fee = _amtIn - net;

        uint256 dIn = uint256(IERC20Metadata(_taIn).decimals());
        uint256 dOut = uint256(IERC20Metadata(_taOut).decimals());

        uint256 rawAmtOut = Math.mulDiv(
            Math.mulDiv(net, 10 ** dOut, 1),
            _exRateIn,
            Math.mulDiv(_exRateOut, 10 ** dIn, 1)
        );

        uint256 retainingDecimal = dOut > _retainingDecimals
            ? dOut - _retainingDecimals
            : 0;
        uint256 _amountOut = rawAmtOut - (rawAmtOut % (10 ** retainingDecimal));

        return
            QuoteData({
                amtIn: _amtIn,
                amtOut: _amountOut,
                fee: fee,
                exRateIn: _exRateIn,
                exRateOut: _exRateOut
            });
    }

    function issue(
        address _taIn, // token address to pay
        address _taOut, // token address to receive
        uint256 _amtIn, // amount to pay
        uint256 _amtOutMin, // the minimum amount out that the user can receive, used for slippage control
        uint256 _exRateIn, // _exRateIn should be 8-decimal value
        uint256 _exRateOut, // _exRateOut should be 8-decimal value
        uint256 _retainingDecimals, // number of decimals to retain for the output amount
        address owner, // owner of the tokens to pay, who made the permit signature
        uint256 deadline, // deadline for the permit signature
        uint8 v, // v, r, s are the parameters for the permit signature
        bytes32 r,
        bytes32 s
    )
        external
        whenNotPaused
        onlyAvailablePair(_taIn, _taOut)
        onlyRole(OPERATION_MANAGER_ROLE)
        nonReentrant
    {
        // Validation 0. Parameter check: non-zero amount
        if (_amtIn == 0 || _amtOutMin == 0) {
            revert InvalidAmount();
        }

        // Validation 0. Parameter check: exrate cannot be zero
        if (_exRateIn == 0 || _exRateOut == 0) {
            revert InvalidExchangeRate();
        }

        // Validation 1. Check if the owner is whitelisted (if whitelist is active)
        checkIsWhitelisted(owner);

        // Validation 2. Check if the calculation is right
        QuoteData memory quoteData = getAmountOut(
            _taIn,
            _taOut,
            _amtIn,
            _exRateIn,
            _exRateOut,
            _retainingDecimals
        );

        {
            // Validation 3. Check if the amount out is not zero
            if (quoteData.amtOut == 0) {
                revert InvalidAmount();
            }

            // Validation 4. Check if the amount out is within the slippage range
            if (quoteData.amtOut < _amtOutMin) {
                revert SlippageExceeded(quoteData.amtOut, _amtOutMin);
            }
            // Validation 5. Check if the contract has enough reserve of the output token
            uint256 reserveOut = getReserve(_taOut);
            if (quoteData.amtOut > reserveOut) {
                revert InsufficientReserve(
                    _taOut,
                    quoteData.amtOut,
                    reserveOut
                );
            }
        }

        if (IERC20(_taIn).allowance(owner, address(this)) < _amtIn) {
            // 1. Call Permit to increase allowance for the token transfer
            try
                IERC20Permit(_taIn).permit(
                    owner,
                    address(this),
                    _amtIn,
                    deadline,
                    v,
                    r,
                    s
                )
            {
                // Permit successful, allowance should be updated
            } catch {
                // permit may have been front-run or otherwise failed
                // anyway, continue and let the transferFrom fail if allowance is insufficient
            }
        }

        // 2. Transfer the tokens from the user to the contract
        uint256 balanceBefore = IERC20(_taIn).balanceOf(address(this));
        IERC20(_taIn).safeTransferFrom(owner, address(this), _amtIn);
        uint256 balanceAfter = IERC20(_taIn).balanceOf(address(this));
        if ((balanceAfter - balanceBefore) != _amtIn) {
            // balanceAfter should be greater than balanceBefore
            revert NotAllowedFeeOnTransfer(_taIn);
        }

        // 3. Transfer the tokens from the contract to the user, after calculating the fee
        balanceBefore = IERC20(_taOut).balanceOf(address(this));
        IERC20(_taOut).safeTransfer(owner, quoteData.amtOut);
        balanceAfter = IERC20(_taOut).balanceOf(address(this));
        if ((balanceBefore - balanceAfter) != quoteData.amtOut) {
            // balanceAfter should be less than balanceBefore
            revert NotAllowedFeeOnTransfer(_taOut);
        }
        // 4. Update the cumulated fees
        cumulatedFees[_taIn] += quoteData.fee;

        emit tokenIssued(
            _taIn,
            _taOut,
            owner,
            _amtIn,
            quoteData.amtOut,
            quoteData.fee,
            _exRateIn,
            _exRateOut
        );
    }

    event tokenIssued(
        address indexed tokenAddressIn,
        address indexed tokenAddressOut,
        address indexed recipient,
        uint256 amountIn,
        uint256 amountOut,
        uint256 fee,
        uint256 rateIn,
        uint256 rateOut
    );

    error InsufficientReserve(
        address tokenAddress,
        uint256 requested,
        uint256 available
    );

    error SlippageExceeded(uint256 amountOut, uint256 amountOutMin);
    error InvalidAmount();
    error InvalidAmountOut();

    // ====================
    // Reserve and Fee Management
    // ====================
    function getReserve(address _ta) public view returns (uint256) {
        uint256 balance = IERC20(_ta).balanceOf(address(this));
        uint256 fee = cumulatedFees[_ta];
        // When balance is less than fee, reserve is considered as zero.
        // If the token balance is less than the recorded fees, the available reserve is treated as zero.
        // This should only occur under exceptional accounting mismatch scenarios.
        if (balance <= fee) {
            return 0;
        } else return (balance - fee);
    }

    event ReserveWithdrawn(
        address indexed tokenAddress,
        address indexed recipient,
        uint256 amount
    );
    function withdrawReserve(
        address _ta, // token address
        address _to, // recipient address
        uint256 _amt // amount to withdraw
    ) external onlyRole(ASSET_MANAGER_ROLE) {
        uint256 reserve = getReserve(_ta);
        if (_amt > reserve) revert InsufficientReserve(_ta, _amt, reserve);
        IERC20(_ta).safeTransfer(_to, _amt);

        emit ReserveWithdrawn(_ta, _to, _amt);
    }

    event FeesWithdrawn(
        address indexed tokenAddress,
        address indexed recipient,
        uint256 amount
    );
    error InsufficientCumulatedFees(
        address tokenAddress,
        uint256 requested,
        uint256 available
    );
    function withdrawFees(
        address _ta, // token address
        address _to, // recipient address
        uint256 _amt // amount to withdraw
    ) external onlyRole(ASSET_MANAGER_ROLE) nonReentrant {
        uint256 feeAmt = cumulatedFees[_ta];
        if (_amt > feeAmt) revert InsufficientCumulatedFees(_ta, _amt, feeAmt);

        uint256 balanceBefore = IERC20(_ta).balanceOf(address(this));

        IERC20(_ta).safeTransfer(_to, _amt);

        uint256 balanceAfter = IERC20(_ta).balanceOf(address(this));
        uint256 balanceDelta = balanceBefore - balanceAfter;

        if (balanceDelta != _amt) {
            // balanceAfter should be less than balanceBefore
            revert NotAllowedFeeOnTransfer(_ta);
        }

        // Reject fee-on-transfer or other non-standard token behaviors
        // reentrancy guard is added for the safety of this step
        cumulatedFees[_ta] = feeAmt - _amt;

        emit FeesWithdrawn(_ta, _to, _amt);
    }

    event EmergencyFeeWithdrawal(
        address indexed tokenAddress,
        address indexed recipient,
        uint256 cumulatedFeeAmount,
        uint256 balanceDelta
    );
    // @notice Emergency-only function to withdraw all accumulated fees for a token and reset cumulatedFees to zero.
    // @dev This function is intended for exceptional cases where normal withdrawFees() cannot be used.
    //      It intentionally does not enforce balance-delta equality and resets fee accounting to zero.
    //      The emitted balanceDelta should be reviewed off-chain for monitoring and reconciliation.
    function emergencyWithdrawFee(
        address _ta,
        address _to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        uint256 feeAmt = cumulatedFees[_ta];

        cumulatedFees[_ta] = 0;

        uint256 balanceBefore = (IERC20(_ta).balanceOf(address(this)));
        IERC20(_ta).safeTransfer(_to, feeAmt);
        uint256 balanceAfter = (IERC20(_ta).balanceOf(address(this)));

        // In emergency withdrawal, we do not revert even if the balance delta does not match the fee amount, but we emit the actual balance delta for monitoring purposes.
        uint256 balanceDelta = balanceBefore > balanceAfter
            ? balanceBefore - balanceAfter
            : 0;

        emit EmergencyFeeWithdrawal(_ta, _to, feeAmt, balanceDelta);
    }

    // ====================
    // Global Error
    // ====================
    error NothingChanged();
    error NotAllowedFeeOnTransfer(address tokenAddress);
}
