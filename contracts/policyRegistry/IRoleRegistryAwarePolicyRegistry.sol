// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IPolicyRegistry} from "./IPolicyRegistry.sol";
import {IRoleRegistry} from "../roleRegistry/IRoleRegistry.sol";

/// @notice PolicyRegistry surface required by consumers that share its RoleRegistry.
interface IRoleRegistryAwarePolicyRegistry is IPolicyRegistry {
    function roleRegistry() external view returns (IRoleRegistry);
}
