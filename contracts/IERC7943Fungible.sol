// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @notice ERC-7943 fungible asset interface.
interface IERC7943Fungible is IERC165 {
    event ForcedTransfer(address indexed from, address indexed to, uint256 amount);
    event Frozen(address indexed account, uint256 amount);

    error ERC7943CannotSend(address account);
    error ERC7943CannotReceive(address account);
    error ERC7943CannotTransfer(address from, address to, uint256 amount);
    error ERC7943InsufficientUnfrozenBalance(address account, uint256 amount, uint256 unfrozen);

    function forcedTransfer(address from, address to, uint256 amount) external returns (bool);
    function setFrozenTokens(address account, uint256 amount) external returns (bool);
    function canSend(address account) external view returns (bool);
    function canReceive(address account) external view returns (bool);
    function getFrozenTokens(address account) external view returns (uint256);
    function canTransfer(address from, address to, uint256 amount) external view returns (bool);
}
