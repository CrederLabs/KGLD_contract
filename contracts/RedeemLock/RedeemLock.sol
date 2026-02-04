// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IRedeemToken is IERC20 {
    function burn(uint256 amount) external;
}

contract RedeemLock is AccessControl {
    enum OrderStatus {
        Pending,
        Stocked,
        Redeemed,
        Burned,
        Canceled
    }

    function statusToString(
        OrderStatus status
    ) public pure returns (string memory) {
        if (status == OrderStatus.Pending) return "Pending";
        if (status == OrderStatus.Stocked) return "Stocked";
        if (status == OrderStatus.Redeemed) return "Redeemed";
        if (status == OrderStatus.Burned) return "Burned";
        if (status == OrderStatus.Canceled) return "Canceled";
        return "Unknown";
    }

    bytes32 public constant REDEEM_MANAGER_ROLE =
        keccak256("REDEEM_MANAGER_ROLE");
    bytes32 public constant ASSET_MANAGER_ROLE =
        keccak256("ASSET_MANAGER_ROLE");

    IRedeemToken public immutable redeemToken;

    constructor(address _redeemToken) {
        redeemToken = IRedeemToken(_redeemToken);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    uint256 public cumulatedCosts;

    struct OrderData {
        address user;
        uint256 goldWeight;
        uint256 extraCost;
        uint256 lockTime;
        OrderStatus status;
    }

    mapping(address => uint256) internal userNonce;
    mapping(address => mapping(uint256 => bytes32)) public userOrders;
    mapping(bytes32 => OrderData) public orders;

    event RedeemLockCreated(
        bytes32 indexed orderId,
        address indexed user,
        uint256 goldWeight,
        uint256 extraCost,
        uint256 lockTime,
        uint256 nonce
    );

    function getNonce(address _user) external view returns (uint256) {
        return userNonce[_user];
    }

    function redeemLock(uint256 _goldWeight, uint256 _extraCost) external {
        uint256 nonce = userNonce[msg.sender];
        require(
            userOrders[msg.sender][nonce] == bytes32(0),
            "Nonce already used"
        );

        uint256 totalAmount = _goldWeight + _extraCost;
        uint256 lockTime = block.timestamp;
        redeemToken.transferFrom(msg.sender, address(this), totalAmount);

        bytes32 orderId = keccak256(
            abi.encodePacked(
                msg.sender,
                lockTime,
                _goldWeight,
                _extraCost,
                nonce
            )
        );

        orders[orderId] = OrderData({
            user: msg.sender,
            goldWeight: _goldWeight,
            extraCost: _extraCost,
            lockTime: lockTime,
            status: OrderStatus.Pending
        });

        emit RedeemLockCreated(
            orderId,
            msg.sender,
            _goldWeight,
            _extraCost,
            lockTime,
            nonce
        );

        userOrders[msg.sender][nonce] = orderId;
        userNonce[msg.sender]++;
    }

    error InvalidOrderStatus(bytes32 orderId);

    function updateOrderStatus(bytes32 orderId, OrderStatus status) internal {
        orders[orderId].status = status;
    }

    event OrderStocked(bytes32 indexed orderId);

    function stockOrder(
        bytes32 orderId
    ) external onlyRole(REDEEM_MANAGER_ROLE) {
        OrderData storage order = orders[orderId];
        if (order.user == address(0)) revert InvalidOrderStatus(orderId);

        if (order.status != OrderStatus.Pending) {
            revert InvalidOrderStatus(orderId);
        }

        updateOrderStatus(orderId, OrderStatus.Stocked);

        emit OrderStocked(orderId);
    }

    event RedeemExecuted(bytes32 indexed orderId, address indexed user);

    function redeemOrder(
        bytes32 orderId
    ) external onlyRole(REDEEM_MANAGER_ROLE) {
        OrderData storage order = orders[orderId];
        if (order.user == address(0)) revert InvalidOrderStatus(orderId);

        if (order.status != OrderStatus.Stocked) {
            revert InvalidOrderStatus(orderId);
        }

        updateOrderStatus(orderId, OrderStatus.Redeemed);

        emit RedeemExecuted(orderId, order.user);
    }

    event RedeemBurned(
        bytes32 indexed orderId,
        address indexed user,
        uint256 goldWeight,
        uint256 extraCost
    );

    function redeemBurn(
        bytes32 orderId
    ) external onlyRole(REDEEM_MANAGER_ROLE) {
        OrderData storage order = orders[orderId];
        if (order.user == address(0)) revert InvalidOrderStatus(orderId);

        if (order.status != OrderStatus.Redeemed)
            revert InvalidOrderStatus(orderId);

        updateOrderStatus(orderId, OrderStatus.Burned);

        redeemToken.burn(order.goldWeight);
        cumulatedCosts += order.extraCost;

        emit RedeemBurned(
            orderId,
            order.user,
            order.goldWeight,
            order.extraCost
        );
    }

    error NotOrderOwner(bytes32 orderId);

    event RedeemRequestCanceled(bytes32 indexed orderId, address indexed user);

    // @notice : User can cancel the redeem request and get refund when the order is pending
    function cancelRedeemRequest(bytes32 orderId) external {
        if (orders[orderId].user != msg.sender) revert NotOrderOwner(orderId);

        if (orders[orderId].status != OrderStatus.Pending)
            revert InvalidOrderStatus(orderId);

        updateOrderStatus(orderId, OrderStatus.Canceled);

        uint256 refundAmount = orders[orderId].goldWeight +
            orders[orderId].extraCost;
        redeemToken.transfer(msg.sender, refundAmount);

        emit RedeemRequestCanceled(orderId, orders[orderId].user);
    }

    event RedeemCanceled(bytes32 indexed orderId, address indexed user);
    // @notice : If the order was redeemed by mistake, the admin can cancel the redeem
    function cancelRedeem(
        bytes32 orderId
    ) external onlyRole(REDEEM_MANAGER_ROLE) {
        if (orders[orderId].status != OrderStatus.Redeemed)
            revert InvalidOrderStatus(orderId);

        updateOrderStatus(orderId, OrderStatus.Stocked);

        emit RedeemCanceled(orderId, orders[orderId].user);
    }

    event CostsWithdrawn(address indexed to, uint256 amount);
    function withdrawCosts(
        address to,
        uint256 amount
    ) external onlyRole(ASSET_MANAGER_ROLE) {
        require(amount <= cumulatedCosts, "Amount exceeds cumulated costs");
        cumulatedCosts -= amount;
        redeemToken.transfer(to, amount);

        emit CostsWithdrawn(to, amount);
    }
}
