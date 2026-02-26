// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {
    AggregatorV3Interface
} from "@chainlink/contracts/src/v0.8/shared/interfaces/AggregatorV3Interface.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    IERC20Metadata
} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

contract CommodityTokenIssuer is AccessControl {
    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);

        _setRoleAdmin(WHITELISTED_ROLE, OPERATION_MANAGER_ROLE);
    }

    // ====================
    // Pair availability
    // ====================
    bool public areAllPairsAvailable = false;
    // @dev availablePairs[keccak256(abi.encodePacked(taIn, taOut))] = bool
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
        if (
            priceFeedForToken[_taIn] == address(0) ||
            priceFeedForToken[_taOut] == address(0) ||
            _taIn == _taOut
        ) {
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

    // ====================
    // Fee management
    // ====================
    uint256 public feeBps = 0; // in basis points (bps), ex) 1% = 100 bps
    mapping(address => uint256) public cumulatedFees;

    error FeeTooHigh(uint256 attemptedFeeBps);
    event FeeBpsChanged(uint256 oldFeeBps, uint256 newFeeBps);
    function setFeeBps(
        uint256 _newFeeBps
    ) external onlyRole(OPERATION_MANAGER_ROLE) {
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
    function setWhitelistStatus(
        bool _status
    ) external onlyRole(OPERATION_MANAGER_ROLE) {
        isWhitelistActive = _status;
        emit WhitelistStatusChanged(_status);
    }

    event WhitelistAddressChanged(address indexed walletAddress, bool status);
    function setWhitelistAddress(
        address _addr,
        bool _status
    ) external onlyRole(OPERATION_MANAGER_ROLE) {
        if (hasRole(WHITELISTED_ROLE, _addr) != _status) {
            if (_status) {
                _grantRole(WHITELISTED_ROLE, _addr);
            } else {
                _revokeRole(WHITELISTED_ROLE, _addr);
            }
            emit WhitelistAddressChanged(_addr, _status);
        }
    }

    error NotWhitelisted(address walletAddress);
    modifier onlyWhitelisted() {
        if (isWhitelistActive) {
            if (!hasRole(WHITELISTED_ROLE, msg.sender)) {
                revert NotWhitelisted(msg.sender);
            }
        }
        _;
    }

    // ====================
    // Pause Management
    // ====================
    bool public isPaused = false;
    event PauseStatusChanged(bool status);
    function setPauseStatus(
        bool _status
    ) external onlyRole(OPERATION_MANAGER_ROLE) {
        isPaused = _status;
        emit PauseStatusChanged(_status);
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
    mapping(address => address) public priceFeedForToken;

    event PriceFeedForTokenSet(
        address indexed tokenAddress,
        address indexed priceFeedAddress
    );
    function setPriceFeedForToken(
        address _token,
        address _priceFeed
    ) external onlyRole(OPERATION_MANAGER_ROLE) {
        priceFeedForToken[_token] = _priceFeed;
        emit PriceFeedForTokenSet(_token, _priceFeed);
    }

    struct QuoteData {
        uint256 amtIn;
        uint256 amtOut;
        uint256 fee;
        int256 rateIn;
        int256 rateOut;
        uint256 tInUpdatedAt;
        uint256 tOutUpdatedAt;
    }

    function getAmountIn(
        address _taIn,
        address _taOut,
        uint256 _amtOut,
        uint256 _retainingDecimals
    )
        public
        view
        onlyAvailablePair(_taIn, _taOut)
        returns (QuoteData memory data)
    {
        uint256 amtIn = 0;
        uint256 high = IERC20(_taIn).totalSupply();

        while (amtIn < high) {
            uint256 mid = (amtIn + high) / 2;
            data = getAmountOut(_taIn, _taOut, mid, _retainingDecimals);

            if (data.amtOut < _amtOut) {
                amtIn = mid + 1;
            } else {
                high = mid;
            }
        }

        data = getAmountOut(_taIn, _taOut, amtIn, _retainingDecimals);
    }

    function getAmountOut(
        address _taIn,
        address _taOut,
        uint256 _amtIn,
        uint256 _retainingDecimals
    )
        public
        view
        onlyAvailablePair(_taIn, _taOut)
        returns (QuoteData memory data)
    {
        data.amtIn = _amtIn;
        data.fee = (_amtIn * feeBps) / 10000;
        _amtIn = _amtIn - data.fee;

        // Precision adjustment: adjust _amtIn to (taInDecimal + taOutDecimal) for calculation
        _amtIn = _amtIn * (10 ** uint256(IERC20Metadata(_taOut).decimals()));

        AggregatorV3Interface pfIn = AggregatorV3Interface(
            priceFeedForToken[_taIn]
        );
        AggregatorV3Interface pfOut = AggregatorV3Interface(
            priceFeedForToken[_taOut]
        );

        (, data.rateIn, , data.tInUpdatedAt, ) = pfIn.latestRoundData();
        (, data.rateOut, , data.tOutUpdatedAt, ) = pfOut.latestRoundData();

        data.amtOut =
            (_amtIn * uint256(data.rateIn) * (10 ** pfOut.decimals())) /
            (uint256(data.rateOut) * (10 ** pfIn.decimals()));

        // Adjust back the precision: adjust amtOut to taOutDecimal
        data.amtOut =
            data.amtOut /
            (10 ** uint256(IERC20Metadata(_taIn).decimals()));

        // Truncate decimals
        uint256 adjDecimals = 10 **
            (IERC20Metadata(_taOut).decimals() - _retainingDecimals);
        data.amtOut = (data.amtOut / adjDecimals) * adjDecimals;
    }

    event tokenIssued(
        address indexed tokenAddressIn,
        address indexed tokenAddressOut,
        uint256 amountIn,
        uint256 amountOut,
        uint256 fee,
        int256 rateIn,
        int256 rateOut,
        address indexed recipient
    );

    error InsufficientBalance(
        address tokenAddress,
        address walletAddress,
        uint256 requested
    );
    error InsufficientReserve(
        address tokenAddress,
        uint256 requested,
        uint256 available
    );
    error SlippageTooLow(
        address tokenAddressOut,
        uint256 amountOut,
        uint256 amountOutMin
    );

    function issue(
        address _taIn,
        address _taOut,
        uint256 _amtIn,
        uint256 _amtOutMin,
        uint256 _retainingDecimals
    ) external onlyWhitelisted whenNotPaused onlyAvailablePair(_taIn, _taOut) {
        if (IERC20(_taIn).balanceOf(msg.sender) < _amtIn)
            revert InsufficientBalance(_taIn, msg.sender, _amtIn);

        QuoteData memory quoteData = getAmountOut(
            _taIn,
            _taOut,
            _amtIn,
            _retainingDecimals
        );

        cumulatedFees[_taIn] += quoteData.fee;

        {
            uint256 reserveOut = getReserve(_taOut);
            if (reserveOut < quoteData.amtOut)
                revert InsufficientReserve(
                    _taOut,
                    quoteData.amtOut,
                    reserveOut
                );
        }
        if (quoteData.amtOut < _amtOutMin)
            revert SlippageTooLow(_taOut, quoteData.amtOut, _amtOutMin);

        IERC20(_taIn).transferFrom(msg.sender, address(this), _amtIn);
        IERC20(_taOut).transfer(msg.sender, quoteData.amtOut);

        emit tokenIssued(
            _taIn,
            _taOut,
            _amtIn,
            quoteData.amtOut,
            quoteData.fee,
            quoteData.rateIn,
            quoteData.rateOut,
            msg.sender
        );
    }

    function getReserve(address _ta) public view returns (uint256) {
        return IERC20(_ta).balanceOf(address(this)) - cumulatedFees[_ta];
    }

    event ReserveWithdrawn(
        address indexed tokenAddress,
        address indexed recipient,
        uint256 amount
    );
    function withdrawReserve(
        address _ta,
        address _to,
        uint256 _amt
    ) external onlyRole(OPERATION_MANAGER_ROLE) {
        uint256 reserve = getReserve(_ta);
        if (_amt > reserve) revert InsufficientReserve(_ta, _amt, reserve);
        IERC20(_ta).transfer(_to, _amt);

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
        address _ta,
        address _to,
        uint256 _amt
    ) external onlyRole(OPERATION_MANAGER_ROLE) {
        uint256 feeAmt = cumulatedFees[_ta];
        if (_amt > feeAmt) revert InsufficientCumulatedFees(_ta, _amt, feeAmt);
        cumulatedFees[_ta] -= _amt;
        IERC20(_ta).transfer(_to, _amt);

        emit FeesWithdrawn(_ta, _to, _amt);
    }

    function depositReserve(address _ta, uint256 _amt) external {
        IERC20(_ta).transferFrom(msg.sender, address(this), _amt);
    }
}
