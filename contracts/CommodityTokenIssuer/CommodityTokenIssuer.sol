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
    // keccak256("OPERATION_MANAGER_ROLE");
    bytes32 public constant OPERATION_MANAGER_ROLE =
        0x261b87b2321a08d52f3b3ee0167bc0ecb9d54938405960f6cfb55fe47cab3c0e;

    // keccak256("WHITELISTED_ROLE");
    bytes32 public constant WHITELISTED_ROLE =
        0x8429d542926e6695b59ac6fbdcd9b37e8b1aeb757afab06ab60b1bb5878c3b49;

    // keccak256("ASSET_MANAGER_ROLE");
    bytes32 public constant ASSET_MANAGER_ROLE =
        0xb1fadd3142ab2ad7f1337ea4d97112bcc8337fc11ce5b20cb04ad038adf99819;

    // ====================
    // Fee management
    // ====================
    uint256 public feeBps = 0; // in basis points (bps), ex) 1% = 100 bps
    mapping(address => uint256) public cumulatedFees;

    error FeeTooHigh(uint256 attemptedFeeBps);
    event FeeBpsChanged(uint256 oldFeeBps, uint256 newFeeBps);
    function setFeeBps(
        uint256 _newFeeBps
    ) external onlyRole(ASSET_MANAGER_ROLE) {
        if (_newFeeBps > 10000) {
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

    function getAmountIn(
        address _taIn,
        address _taOut,
        uint256 _amtOut, // Desired token amount to recieve, after fee deduction
        uint256 _exRateIn, // Exchange rate for the input token, should be 8-decimal value.
        uint256 _exRateOut, // Exchange rate for the output token, should be 8-decimal value.
        uint256 _retainingDecimals
    ) public view returns (QuoteData memory data) {
        uint256 amtIn = 0;
        uint256 h = IERC20(_taIn).totalSupply();

        while (amtIn < h) {
            uint256 mid = (amtIn + h) / 2;
            data = getAmountOut(
                _taIn,
                _taOut,
                mid,
                _exRateIn,
                _exRateOut,
                _retainingDecimals
            );

            if (data.amtOut < _amtOut) {
                amtIn = mid + 1;
            } else {
                h = mid;
            }
        }

        data = getAmountOut(
            _taIn,
            _taOut,
            amtIn,
            _exRateIn,
            _exRateOut,
            _retainingDecimals
        );
    }
    function getAmountOut(
        address _taIn,
        address _taOut,
        uint256 _amtIn, // Token amount to pay, before fee deduction
        uint256 _exRateIn, // Exchange rate for the input token, should be 8-decimal value.
        uint256 _exRateOut, // Exchange rate for the output token, should be 8-decimal value.
        uint256 _retainingDecimals
    ) public view returns (QuoteData memory) {
        uint256 fee = Math.mulDiv(_amtIn, feeBps, 10000);

        uint256 dIn = uint256(IERC20Metadata(_taIn).decimals());
        uint256 dOut = uint256(IERC20Metadata(_taOut).decimals());

        // The full calculation is: ((_amtIn - fee) * 10 ** dOut * _exRateIn) / (10 ** dIn * _exRateOut)
        uint256 rawAmtOut = Math.mulDiv(
            Math.mulDiv(sub256(_amtIn, fee), 10 ** dOut, 10 ** dIn),
            _exRateIn,
            _exRateOut
        );

        uint256 retainingDecimal = sub256(dOut, _retainingDecimals);

        return
            QuoteData({
                amtIn: _amtIn,
                amtOut: sub256(
                    rawAmtOut,
                    (rawAmtOut % (10 ** retainingDecimal))
                ), // round down to the retaining decimals
                fee: fee,
                exRateIn: _exRateIn,
                exRateOut: _exRateOut
            });
    }

    function issue(
        address _taIn, // token address to pay
        address _taOut, // token address to receive
        uint256 _amtIn, // amount to pay
        uint256 _amtOut, // _amtOut is calculated from off-chain and passed in as a parameter, _amtOut = (_amtIn - fee) * _exRateIn / _exRateOut
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
        // Validation 1. Check if the owner is whitelisted (if whitelist is active)
        checkIsWhitelisted(owner);

        {
            // Validation 2. Check if the contract has enough reserve of the output token
            uint256 reserveOut = getReserve(_taOut);
            if (_amtOut > reserveOut) {
                revert InsufficientReserve(_taOut, _amtOut, reserveOut);
            }
        }

        // Validation 3. Check if the calculation is right
        QuoteData memory quoteData = getAmountOut(
            _taIn,
            _taOut,
            _amtIn,
            _exRateIn,
            _exRateOut,
            _retainingDecimals
        );

        if (_amtOut != quoteData.amtOut) {
            revert AmountOutCalculationMismatch(
                _amtIn,
                quoteData.fee,
                _amtOut,
                quoteData.amtOut
            );
        }

        // 1. Call Permit to increase allowance for the token transfer
        IERC20Permit(_taIn).permit(
            owner,
            address(this),
            _amtIn,
            deadline,
            v,
            r,
            s
        );
        // 2. Transfer the tokens from the user to the contract
        uint256 balanceBefore = IERC20(_taIn).balanceOf(address(this));
        IERC20(_taIn).safeTransferFrom(owner, address(this), _amtIn);
        uint256 balanceAfter = IERC20(_taIn).balanceOf(address(this));
        if (sub256(balanceAfter, balanceBefore) != _amtIn) {
            revert NotAllowedFeeOnTransfer(_taIn);
        }

        // 3. Transfer the tokens from the contract to the user, after calculating the fee
        balanceBefore = IERC20(_taOut).balanceOf(address(this));
        IERC20(_taOut).safeTransfer(owner, _amtOut);
        balanceAfter = IERC20(_taOut).balanceOf(address(this));
        if (sub256(balanceBefore, balanceAfter) != _amtOut) {
            revert NotAllowedFeeOnTransfer(_taOut);
        }
        // 4. Update the cumulated fees
        cumulatedFees[_taIn] += quoteData.fee;

        emit tokenIssued(
            _taIn,
            _taOut,
            owner,
            _amtIn,
            _amtOut,
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

    error NotAllowedFeeOnTransfer(address tokenAddress);

    error InsufficientReserve(
        address tokenAddress,
        uint256 requested,
        uint256 available
    );

    error AmountOutCalculationMismatch(
        uint256 amountIn, // amount in from the parameter
        uint256 fee, // fee amount
        uint256 amountOut, // amount out from the parameter
        uint256 expectedAmountOut // amount out calculated from the exchange rate
    );

    // ====================
    // Reserve and Fee Management
    // ====================
    function getReserve(address _ta) public view returns (uint256) {
        uint256 balance = IERC20(_ta).balanceOf(address(this));
        uint256 fee = cumulatedFees[_ta];

        return sub256(balance, fee);
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
    ) external onlyRole(ASSET_MANAGER_ROLE) {
        uint256 feeAmt = cumulatedFees[_ta];
        if (_amt > feeAmt) revert InsufficientCumulatedFees(_ta, _amt, feeAmt);
        cumulatedFees[_ta] = sub256(cumulatedFees[_ta], _amt);
        IERC20(_ta).safeTransfer(_to, _amt);

        emit FeesWithdrawn(_ta, _to, _amt);
    }

    // ====================
    // Global Error
    // ====================
    error NothingChanged();

    // ====================
    // Utils
    // ====================
    function sub256(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a - b : 0;
    }
}
