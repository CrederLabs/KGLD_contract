# KGLD Contracts — 2026-10 Audit Renewal

Solidity sources and ABIs for the October 2026 KGLD contract renewal audit.

## Audit scope

The audit covers all 19 Solidity files under `contracts/`, including the seven deployable contracts below and their supporting interfaces and abstract base contracts.

| Contract | Source | ABI |
|---|---|---|
| CommodityToken | [contracts/CommodityToken.sol](contracts/CommodityToken.sol) | [CommodityToken.abi.json](ABI/CommodityToken.abi.json) |
| CommodityTokenProxy | [contracts/CommodityTokenProxy.sol](contracts/CommodityTokenProxy.sol) | [CommodityTokenProxy.abi.json](ABI/CommodityTokenProxy.abi.json) |
| Controller | [contracts/controller/Controller.sol](contracts/controller/Controller.sol) | [Controller.abi.json](ABI/Controller.abi.json) |
| PolicyRegistry | [contracts/policyRegistry/PolicyRegistry.sol](contracts/policyRegistry/PolicyRegistry.sol) | [PolicyRegistry.abi.json](ABI/PolicyRegistry.abi.json) |
| AccessControlRoleRegistry | [contracts/roleRegistry/AccessControlRoleRegistry.sol](contracts/roleRegistry/AccessControlRoleRegistry.sol) | [AccessControlRoleRegistry.abi.json](ABI/AccessControlRoleRegistry.abi.json) |
| Treasury | [contracts/treasury/Treasury.sol](contracts/treasury/Treasury.sol) | [Treasury.abi.json](ABI/Treasury.abi.json) |
| TreasuryProxy | [contracts/treasury/TreasuryProxy.sol](contracts/treasury/TreasuryProxy.sol) | [TreasuryProxy.abi.json](ABI/TreasuryProxy.abi.json) |

Supporting code is located in `contracts/IERC7943Fungible.sol`, `contracts/controller/I*.sol`, `contracts/policyRegistry/`, and `contracts/roleRegistry/`. OpenZeppelin dependency versions are pinned in `package-lock.json`.

Deployment scripts, tests, mocks, and local environment files such as `.env` are excluded from the audit submission.

## Build configuration

| Setting | Value |
|---|---|
| Solidity | `0.8.28` |
| EVM target | `cancun` |
| Optimizer | enabled, `runs: 100` |
| viaIR | `false` |
| Hardhat | `2.27.1` |
| OpenZeppelin Contracts | `5.4.0` |
| OpenZeppelin Contracts Upgradeable | `5.4.0` |

Compiler settings are defined in [hardhat.config.js](hardhat.config.js). Dependency versions are locked in [package-lock.json](package-lock.json).

```sh
npm ci --ignore-scripts
```

The current Hardhat `networks` configuration references deployment environment variables. To compile locally without those variables, use a separate configuration that preserves the `solidity` settings and overrides `networks` with `{}`. Selecting `--network hardhat` alone does not bypass validation of other network configurations.

The seven files under `ABI/` match the `abi` fields of the artifacts compiled from the current sources with the settings above.

## Source snapshot hashes

The SHA-256 hashes below identify the contents of the 19 in-scope source files, compiler configuration, and dependency lockfile. Update these hashes when any corresponding file changes. Include the commit hash containing this snapshot in the final audit submission.

```text
18e3655470062422219aa68b69b4a08e6dc6afa2598ef54b77a4bf5050240994  contracts/CommodityToken.sol
af5ad9a2811e5c0cfe9eaf1dfc46fb47bbac97838ea549a8a0d5d902bfbaeb40  contracts/CommodityTokenProxy.sol
dfa1482462907e5ab3a6d71b60df105e5f354d1273189da5f7394eb7f63faaab  contracts/IERC7943Fungible.sol
a395c4e0956ab9b3fff7075937c41c653552617a9f386705daf133943ce55772  contracts/controller/Controller.sol
f0bbcc9ae0bb1d77e49f5569d346ada02d8e991b2043b8581168bdd200054b8d  contracts/controller/IPriceValidator.sol
06871bfa23f3ee7086699b7b9c1a8572e79c493cfe0e711189850cfe7a484776  contracts/controller/ISignatureTransfer.sol
11f5d0ffeedace1790b2dc4475f1be18797947b0d8697c8dcb3afe5c5e7bf7ce  contracts/controller/ITreasury.sol
5347c18a4b6bd14313c5cabc2fd124bcf05c96ddc4d7ef123cec5e9e4f9c766a  contracts/policyRegistry/IPolicyRegistry.sol
a140313e40602a54ef3cc888d7f0f4fde7b9661ada2bdf4319e158cc7683c3ed  contracts/policyRegistry/IRoleAdminPolicyRegistry.sol
34c93c22f09e12fec56e58b5dc493e3f1f4f73e26ff3a259f649c77cdc571c0d  contracts/policyRegistry/IRoleRegistryAwarePolicyRegistry.sol
255cc26a2952d32d5b72051d5f726a85d094c904f0a4cfacdfbbe322333a5566  contracts/policyRegistry/PolicyRegistry.sol
0ed9981074626217800eac3e2597fad0f5beec66c1857ac0c4011b4e8f1d31f5  contracts/policyRegistry/PolicyRegistryClient.sol
b222438bc6a2a9a6b0f451faac656ffcc18f12a3cfa22356a98d7a91dc81e9f6  contracts/policyRegistry/PolicyRegistryClientUpgradeable.sol
d36b43d6c551d7018414e617f81512d4d98cf2b83b93d508e6b378eba0f1c67d  contracts/roleRegistry/AccessControlRoleRegistry.sol
933433bf8513c46cd24b5c67a5a2340610fe7ccd5f85497b791b6ce67d2ce055  contracts/roleRegistry/IRoleRegistry.sol
01d2718109b82004376f06565baec235837afc00820324fac0f36a8c72b25d31  contracts/roleRegistry/RoleRegistryClient.sol
89c91a66ced6a1cc23f4cfb6d4a1325f1b5538271900042c794a2194536a6ca8  contracts/roleRegistry/RoleRegistryClientUpgradeable.sol
0f63de06096d6ed14b55a7d81a369899783c9198f0eedfaf08d524522cbb8b71  contracts/treasury/Treasury.sol
5b7ce570ae1763438815aa9c5c5a1e1a46093886c128aba405b100e730211907  contracts/treasury/TreasuryProxy.sol
36ff177d9dd1945f95fbc64d994ec93719d321c5d306cc042368f30d23b21b4d  hardhat.config.js
5ce6a8ba3a01fd9a90e6776905b88e895eec227a7f6617482d3fe7e567b0a127  package-lock.json
```
