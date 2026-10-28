# KGLD Contracts — October 2026 Audit Feedback, Round 2

Prepared: 2026-10-28

Solidity sources and ABIs for the second feedback round of the October 2026 KGLD renewal audit.

## Package contents

| Reference | Commit or branch |
| --- | --- |
| Original audit submission | `b2f431b29b2143099d7b6f2ad407ce73c5ef209e` |
| First preliminary-report feedback | `ef87550745ec6f831076007ac225a44612a2258b` |
| Second-feedback branch | `audit-renewal-2026-10-feedback-2` |

The file counts, change summary, and hashes below describe the current working-tree snapshot on the second-feedback branch. The first-feedback commit is the comparison baseline, not the commit containing these additional changes. Record the resulting commit hash with the second-feedback submission after committing the snapshot.

Compared with the original submission, seven Solidity source files are modified, one is deleted, and eleven are unchanged. The deleted file is `contracts/policyRegistry/PolicyRegistryClient.sol`; its removal was already included in the first-feedback commit.

Compared with the first-feedback commit, two Solidity source files are modified and sixteen are unchanged:

| File | Second-feedback change |
| --- | --- |
| [CommodityToken.sol](contracts/CommodityToken.sol) | Migration configuration, Treasury handling, vault issuance, compliance queries, signature validation, and policy-binding documentation. |
| [ITreasury.sol](contracts/controller/ITreasury.sol) | Documentation only: identifies vault issuance as another consumer of the existing interface. |
| [CommodityToken.abi.json](ABI/CommodityToken.abi.json) | Updated constructor, getters, errors, `canTransferFor`, and `vaultMint` signature. The other six ABI files are unchanged from the first-feedback commit. |

Tests, mocks, deployment scripts, environment files, private keys, and `testnetDeploy/` are outside this audit package.

## Audit scope

The scope contains all 18 Solidity files under `contracts/`. The seven deployable contracts are listed below; the remaining files are their interfaces and abstract base contracts.

| Contract | Source | ABI |
| --- | --- | --- |
| CommodityToken | [contracts/CommodityToken.sol](contracts/CommodityToken.sol) | [CommodityToken.abi.json](ABI/CommodityToken.abi.json) |
| CommodityTokenProxy | [contracts/CommodityTokenProxy.sol](contracts/CommodityTokenProxy.sol) | [CommodityTokenProxy.abi.json](ABI/CommodityTokenProxy.abi.json) |
| Controller | [contracts/controller/Controller.sol](contracts/controller/Controller.sol) | [Controller.abi.json](ABI/Controller.abi.json) |
| PolicyRegistry | [contracts/policyRegistry/PolicyRegistry.sol](contracts/policyRegistry/PolicyRegistry.sol) | [PolicyRegistry.abi.json](ABI/PolicyRegistry.abi.json) |
| AccessControlRoleRegistry | [contracts/roleRegistry/AccessControlRoleRegistry.sol](contracts/roleRegistry/AccessControlRoleRegistry.sol) | [AccessControlRoleRegistry.abi.json](ABI/AccessControlRoleRegistry.abi.json) |
| Treasury | [contracts/treasury/Treasury.sol](contracts/treasury/Treasury.sol) | [Treasury.abi.json](ABI/Treasury.abi.json) |
| TreasuryProxy | [contracts/treasury/TreasuryProxy.sol](contracts/treasury/TreasuryProxy.sol) | [TreasuryProxy.abi.json](ABI/TreasuryProxy.abi.json) |

Supporting code is under `contracts/IERC7943Fungible.sol`, `contracts/controller/I*.sol`, `contracts/policyRegistry/`, and `contracts/roleRegistry/`.

## Second-feedback changes

- **Migration configuration:** The implementation constructor accepts an immutable `REINITIALIZE_CONFIG_HASH` and disables initializers on the implementation itself. Legacy `reinitialize()` requires a nonzero hash matching `keccak256(abi.encode(config))`. A zero hash disables legacy migration while allowing initialization of a new proxy.
- **Treasury protection:** The configured Treasury cannot be frozen or used as the source of a forced transfer. Its own regular transfer and approval eligibility is exempt from the corresponding policies; counterparty checks, pause, roles, and balance checks still apply.
- **Vault issuance:** `vaultMint(address to, uint256 amount)` is replaced by `vaultMint(uint256 amount)`. It mints to the Token Proxy and deposits the tokens into Treasury's `UNISSUED_KGLD` bucket atomically. The Token Proxy must hold `TREASURY_MANAGER_ROLE`; the bucket's deposit policy must permit the deposit. The bridge mint limit is not consumed.
- **Compliance queries:** `canTransferFor(executor, from, to, amount)` checks compliance for a specified executor. `canTransfer` delegates to it using the caller as executor. This query does not grant transfer authority or validate allowance or total balance sufficiency.
- **Signature validation:** ECDSA recovery is attempted regardless of whether the signer has code, followed by ERC-1271 validation if recovery does not authenticate the signer.
- **Policy binding:** Documentation requires policy IDs from validated creation receipts or same-transaction return values, rather than predicted IDs. Existence checks alone do not establish a policy's provenance, administrator, or members.

The first-feedback handoff notes recorded KGL-22 as addressed by KGL-05 and did not identify remediation commits for KGL-08, KGL-11, KGL-19, KGL-20, or KGL-21. The summary above describes the additional source changes; it does not assign updated finding-resolution statuses.

## Build configuration and ABIs

| Setting | Value |
| --- | --- |
| Solidity | `0.8.28` |
| EVM target | `cancun` |
| Optimizer | enabled, `runs: 100` |
| viaIR | `false` |
| Hardhat | `2.27.1` |
| OpenZeppelin Contracts | `5.4.0` |
| OpenZeppelin Contracts Upgradeable | `5.4.0` |

Compiler settings are defined in [hardhat.config.js](hardhat.config.js). Dependency versions are locked in [package-lock.json](package-lock.json). Both files are included in this repository.

`ABI/` contains the seven contract ABI files listed above. The change summary identifies the interface changes included in this snapshot; the hashes below identify the exact source and ABI files.

## Snapshot hashes

The SHA-256 hashes below cover all 18 Solidity sources, seven ABI files, the compiler configuration, and the dependency lockfile. Paths are relative to the repository root; README itself is excluded. Update the hashes and comparison counts whenever the corresponding files change.

```text
73ef4472024870f5a63826c2e011672d296718f1ae0501a4e93879c2eea0d0cf  ABI/AccessControlRoleRegistry.abi.json
eb63cefe42a79931d423718b47989bcefb71d89a74eff5d65ded1f3b969a6f65  ABI/CommodityToken.abi.json
8fd9a4c1478f442384dcd6b8e59ca5044404cf68611f71a23318cb29b5ab550c  ABI/CommodityTokenProxy.abi.json
37fd0c271852a9d797cd703819b9673c8af951e6ccdd17e95d94e3073703aea5  ABI/Controller.abi.json
b00ce1a5540f1d66593ab562d91839140e2ba67f56beab3283aa4c10c88d5e72  ABI/PolicyRegistry.abi.json
a5f559ce4f9f3178528690cbc694ffd281eeac97377698fb4f3b264d96c4cfd9  ABI/Treasury.abi.json
ea220791272dd54a823d179997056e2a3a5b94cd8cfcf4a912f335ea4b4464da  ABI/TreasuryProxy.abi.json
1a904d04caebc952885dc5694d3679e2c3c103c22f41629c77d68178cee5a2b0  contracts/CommodityToken.sol
af5ad9a2811e5c0cfe9eaf1dfc46fb47bbac97838ea549a8a0d5d902bfbaeb40  contracts/CommodityTokenProxy.sol
dfa1482462907e5ab3a6d71b60df105e5f354d1273189da5f7394eb7f63faaab  contracts/IERC7943Fungible.sol
f9481907ddb0e5f5870f16ab20c78ac2e4761da82d07f4a5287c6988d4c46adb  contracts/controller/Controller.sol
f0bbcc9ae0bb1d77e49f5569d346ada02d8e991b2043b8581168bdd200054b8d  contracts/controller/IPriceValidator.sol
06871bfa23f3ee7086699b7b9c1a8572e79c493cfe0e711189850cfe7a484776  contracts/controller/ISignatureTransfer.sol
e1f8b3eddcc47eb33b9e87b4b1a5355f2323e883f270ae718d9081cc8d8f4924  contracts/controller/ITreasury.sol
5347c18a4b6bd14313c5cabc2fd124bcf05c96ddc4d7ef123cec5e9e4f9c766a  contracts/policyRegistry/IPolicyRegistry.sol
a140313e40602a54ef3cc888d7f0f4fde7b9661ada2bdf4319e158cc7683c3ed  contracts/policyRegistry/IRoleAdminPolicyRegistry.sol
34c93c22f09e12fec56e58b5dc493e3f1f4f73e26ff3a259f649c77cdc571c0d  contracts/policyRegistry/IRoleRegistryAwarePolicyRegistry.sol
fb3fb793d65971a8c811aa1a6d94cab889c1f613b6004245e2f4fb7c3b6de6bf  contracts/policyRegistry/PolicyRegistry.sol
b222438bc6a2a9a6b0f451faac656ffcc18f12a3cfa22356a98d7a91dc81e9f6  contracts/policyRegistry/PolicyRegistryClientUpgradeable.sol
3795620df0e4f6feb6e0a19679892d97220d24bb781cadf23f7d94dd7959947c  contracts/roleRegistry/AccessControlRoleRegistry.sol
933433bf8513c46cd24b5c67a5a2340610fe7ccd5f85497b791b6ce67d2ce055  contracts/roleRegistry/IRoleRegistry.sol
c7cc2170f6170a57cd4562a0c0328c8d51fc75af9e517adbdc8cd0444414bd54  contracts/roleRegistry/RoleRegistryClient.sol
89c91a66ced6a1cc23f4cfb6d4a1325f1b5538271900042c794a2194536a6ca8  contracts/roleRegistry/RoleRegistryClientUpgradeable.sol
1bd1769b54f840644443b28742fabffa9a7136a1da57d3e896958462e9b83b08  contracts/treasury/Treasury.sol
5b7ce570ae1763438815aa9c5c5a1e1a46093886c128aba405b100e730211907  contracts/treasury/TreasuryProxy.sol
36ff177d9dd1945f95fbc64d994ec93719d321c5d306cc042368f30d23b21b4d  hardhat.config.js
5ce6a8ba3a01fd9a90e6776905b88e895eec227a7f6617482d3fe7e567b0a127  package-lock.json
```
