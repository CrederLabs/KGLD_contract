// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Fixed Controller-facing interface for token-pair price validation.
/// @dev Controller selects the validator by token pair. Validators own their token-pair
/// configuration, pricing formula, oracle access and validation settings.
interface IPriceValidator {
    /// @dev Called before funds move. Controller rejects false; validator reverts also reject the trade.
    /// @param tokenInAmount Input amount excluding fees, in the configured input token's base units.
    /// @param tokenOutAmount Output amount in the configured output token's base units.
    /// @return validated True to accept the price, false to reject it.
    function validatePrice(uint256 tokenInAmount, uint256 tokenOutAmount)
        external view returns (bool validated);
}
