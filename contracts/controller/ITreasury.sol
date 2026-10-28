// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Treasury operations used by vault issuance, trade settlement and redemption.
interface ITreasury {
    function deposit(address token, bytes32 bucket, uint256 amount) external;

    function withdraw(
        address depositTo,
        address token,
        bytes32 bucket,
        uint256 amount
    ) external;

    function bucketTransfer(
        address token,
        bytes32 bucketFrom,
        bytes32 bucketTo,
        uint256 amount
    ) external;

    function burnBucket(address token, bytes32 bucket, uint256 amount) external;

    function depositAndWithdraw(
        address depositToken,
        bytes32 depositBucket,
        uint256 depositAmount,
        address withdrawTo,
        address withdrawToken,
        bytes32 withdrawBucket,
        uint256 withdrawAmount
    ) external;
}
