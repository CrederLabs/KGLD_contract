// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

/*
    @title KGLDToken
    @dev ERC20 Token representing Korea Gold-Backed Token (KGLD) with upgradeability, access control, pausing, and freezing features.
 */
contract KGLDToken is
    Initializable,
    UUPSUpgradeable,
    ERC20Upgradeable,
    ERC20PermitUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable
{
    // ====================
    // Roles
    // ====================
    // @notice Default admin role for AccessControl is Declared in AccessControlUpgradeable : 0x00
    // @notice UPGRADER_ROLE is used when authorizing upgrades
    // keccak256("UPGRADER_ROLE");
    bytes32 public constant UPGRADER_ROLE =
        0x189ab7a9244df0848122154315af71fe140f3db0fe014031783b0946b8c9d2e3;
    // @notice PAUSER_ROLE is used to pause and unpause the contract
    // keccak256("PAUSER_ROLE");
    bytes32 public constant PAUSER_ROLE =
        0x65d7a28e3265b37a6474929f336521b332c1681b933f6cb9f3376673440d862a;
    // @notice VAULT_MINTER_ROLE is used to mint tokens(backed by vault assets)
    // keccak256("VAULT_MINTER_ROLE");
    bytes32 public constant VAULT_MINTER_ROLE =
        0x98e4415ac43dc65a73fb377c77c834c9fba44fb3f81dc603d1f33e6023519e07;
    // @notice MINTER_ROLE is used to mint tokens
    // keccak256("MINTER_ROLE");
    bytes32 public constant MINTER_ROLE =
        0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6;
    // @notice BURNER_ROLE is used to burn tokens
    // keccak256("BURNER_ROLE");
    bytes32 public constant BURNER_ROLE =
        0x3c11d16cbaffd01df69ce1c404f6340ee057498f5f00246190ea54220576a848;
    // @notice RISK_MANAGER_ROLE is used to manage risk-related functions such as pausing and freezing accounts
    // keccak256("RISK_MANAGER_ROLE");
    bytes32 public constant RISK_MANAGER_ROLE =
        0xb2e3ee861706f0756afea8a5257301f83561f9ac10b8f43b771dc928566f8c61;

    // @notice FROZEN_ROLE is used to identify frozen accounts
    // @notice RISK_MANAGER_ROLE can add/remove accounts to/from this role
    // keccak256("FROZEN_ROLE");
    bytes32 public constant FROZEN_ROLE =
        0x692fe418ed64ac7ff16f79ea7dade91c969e167ccb96f56f1a4cc50061b6005c;

    // @notice MINT_APPROVER_ROLE is used to sign mint approvals
    // keccak256("MINT_APPROVER_ROLE");
    bytes32 public constant MINT_APPROVER_ROLE =
        0x729e7093b317e8cb328751b2fec56d2c53d4821956f473a16b7334aeb4bd61bd;
    // @notice UPGRADE_AUDITOR_ROLE is used to audit new implementation
    // keccak256("UPGRADE_AUDITOR_ROLE");
    bytes32 public constant UPGRADE_AUDITOR_ROLE =
        0x518cb1580b90d89361b4998d16c498d3d1e93d39fec155f2214eee68154fb72e;

    // ====================
    // Initializer
    // ====================
    function initialize(address initialAdmin) public initializer onlyProxy {
        string memory _name = "Korea Gold-Backed Token";
        string memory _symbol = "KGLD";

        __ERC20_init(_name, _symbol);

        // including initialize EIP712 domain separator
        __ERC20Permit_init(_name);
        __AccessControl_init();
        __Pausable_init();

        // Grant Admin role to the initial admin
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);

        // RISK_MANAGER_ROLE can manage FROZEN_ROLE
        _setRoleAdmin(FROZEN_ROLE, RISK_MANAGER_ROLE);
    }

    // ====================
    // UUPS Authorization
    // ====================
    // @dev _authorizeUpgrade function here is commented because the function is overridden later with additional checks.
    // function _authorizeUpgrade(
    //     address newImplementation
    // ) internal override onlyProxy onlyRole(UPGRADER_ROLE) {}

    // ====================
    // Pause Functions
    // ====================
    // @notice Pause all token transfers and approvals
    // @dev Only accounts with the PAUSER_ROLE can call this function
    function pause() external onlyProxy onlyRole(PAUSER_ROLE) {
        _pause();
    }

    // @notice Unpause all token transfers and approvals
    // @dev Only accounts with the PAUSER_ROLE can call this function
    function unpause() external onlyProxy onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    // ====================
    // Risk Manager Functions
    // ====================
    function freeze(address _account) external onlyProxy {
        grantRole(FROZEN_ROLE, _account);
        emit Frozen(_account);
    }

    function unfreeze(address _account) external onlyProxy {
        revokeRole(FROZEN_ROLE, _account);
        emit Unfrozen(_account);
    }

    function selfFreeze() external onlyProxy {
        _grantRole(FROZEN_ROLE, _msgSender());
        emit Frozen(_msgSender());
    }

    error AccountNotFrozen(address account);
    function wipeFrozenAccount(
        address _account
    ) external onlyProxy onlyRole(RISK_MANAGER_ROLE) {
        if (!isFrozen(_account)) {
            revert AccountNotFrozen(_account);
        }
        uint256 frozenBalance = balanceOf(_account);
        _updateForWipe(_account, frozenBalance);
        emit Wiped(_account, frozenBalance);
    }

    function isFrozen(address _account) public view onlyProxy returns (bool) {
        return hasRole(FROZEN_ROLE, _account);
    }

    error FrozenRoleRenounceAttempt();
    function renounceRole(
        bytes32 role,
        address callerConfirmation
    ) public override onlyProxy {
        if (role == FROZEN_ROLE) {
            revert FrozenRoleRenounceAttempt();
        }
        super.renounceRole(role, callerConfirmation);
    }

    error AccountFrozen(address account);

    // ====================
    // Update ERC20 Hook
    // ====================
    function _update(
        address _from,
        address _to,
        uint256 _amount
    ) internal override whenNotPaused onlyProxy {
        if (isFrozen(_from)) {
            revert AccountFrozen(_from);
        }
        if (isFrozen(_to)) {
            revert AccountFrozen(_to);
        }

        super._update(_from, _to, _amount);
    }

    // @notice Internal function to update balances when wiping a frozen account
    // @notice normal _update function does not work when the account is frozen
    function _updateForWipe(
        address _account,
        uint256 _amount
    ) internal whenNotPaused onlyProxy {
        super._update(_account, address(0), _amount);
    }

    // ====================
    // Nonce Authorization (EIP712)
    // ====================
    // keccak256(abi.encode(uint256(keccak256(bytes("EIP712.USED_NONCE"))) - 1)) & ~bytes32(uint256(0xff));
    bytes32 private constant AUTHORIZATION_STATE_STORAGE =
        0xaedccaaf8ccffebfb1c1fab02788f133cca08385faadbe1e213b04d3cebadd00;

    struct AuthorizationStorage {
        mapping(address => mapping(bytes32 => bool)) usedNonces;
    }

    function _getUsedNoncesStorage()
        internal
        pure
        returns (AuthorizationStorage storage store)
    {
        bytes32 slot = AUTHORIZATION_STATE_STORAGE;
        assembly {
            store.slot := slot
        }
    }

    function authorizationState(
        address authorizer,
        bytes32 nonce
    ) external view returns (bool) {
        AuthorizationStorage storage store = _getUsedNoncesStorage();
        return store.usedNonces[authorizer][nonce];
    }

    function cancelAuthorization(
        address authorizer,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external onlyProxy {
        // Verify Signature
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "CancelAuthorization(address authorizer,bytes32 nonce)"
                ),
                authorizer,
                nonce
            )
        );

        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ecrecover(hash, v, r, s);

        if (signer != authorizer) {
            revert InvalidSignature();
        }

        // Mark the nonce as used to prevent future use
        AuthorizationStorage storage store = _getUsedNoncesStorage();
        store.usedNonces[authorizer][nonce] = true;
        emit AuthorizationUsed(authorizer, nonce);
    }

    error InvalidAuthorization(address authorizer, bytes32 nonce);

    // ====================
    // ERC20 Functions(Permissioned)
    // ====================
    function mint(address _to, uint256 _amount) external onlyRole(MINTER_ROLE) {
        _mint(_to, _amount);
        emit Minted(_to, _amount);
    }

    function burn(uint256 _amount) external onlyRole(BURNER_ROLE) onlyProxy {
        _burn(_msgSender(), _amount);
        emit Burned(_msgSender(), _amount);
    }

    // ====================
    // Approved Mint
    // ====================

    error AuthorizationExpired(
        uint256 validAfter,
        uint256 validBefore,
        uint256 currentTime
    );
    error InvalidSignature();

    function mintWithAuthorization(
        address to,
        uint256 amount,
        bytes32 nonce,
        uint256 validAfter,
        uint256 validBefore,
        uint256 vaultedWeight,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external onlyRole(VAULT_MINTER_ROLE) onlyProxy {
        // Check time validity
        if (block.timestamp < validAfter || block.timestamp > validBefore) {
            revert AuthorizationExpired(
                validAfter,
                validBefore,
                block.timestamp
            );
        }

        // Verify Signature
        // if parameters are different from those signed data, ecrecover will return a different address
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "MintWithAuthorization(address to,uint256 amount,bytes32 nonce,uint256 validAfter,uint256 validBefore)"
                ),
                to,
                amount,
                nonce,
                validAfter,
                validBefore
            )
        );

        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ecrecover(hash, v, r, s);

        if (!hasRole(MINT_APPROVER_ROLE, signer)) {
            revert InvalidSignature();
        }

        // Check nonce validity
        AuthorizationStorage storage store = _getUsedNoncesStorage();
        if (store.usedNonces[signer][nonce]) {
            revert InvalidAuthorization(signer, nonce);
        }

        // Available when signer == approver && msg.sender == MINTER_ROLE
        _mint(to, amount);
        emit Minted(to, amount);
        emit VaultedWeight(vaultedWeight);

        // Mark the nonce as used
        store.usedNonces[signer][nonce] = true;
        emit AuthorizationUsed(msg.sender, nonce);
    }

    // ====================
    // ERC20 Functions(Public)
    // ====================
    function name() public view override onlyProxy returns (string memory) {
        return super.name();
    }

    function symbol() public view override onlyProxy returns (string memory) {
        return super.symbol();
    }

    function decimals() public view override onlyProxy returns (uint8) {
        return super.decimals();
    }

    function _approve(
        address _owner,
        address _spender,
        uint256 _amount,
        bool emitEvent
    ) internal override whenNotPaused onlyProxy {
        //Frozen Accounts must not be able to approve and to be approved
        if (isFrozen(_owner)) {
            revert AccountFrozen(_owner);
        }
        if (isFrozen(_spender)) {
            revert AccountFrozen(_spender);
        }

        super._approve(_owner, _spender, _amount, emitEvent);
    }

    function balanceOf(
        address _account
    ) public view override onlyProxy returns (uint256) {
        return super.balanceOf(_account);
    }

    function totalSupply() public view override onlyProxy returns (uint256) {
        return super.totalSupply();
    }

    function allowance(
        address _owner,
        address _spender
    ) public view override onlyProxy returns (uint256) {
        return super.allowance(_owner, _spender);
    }

    function transfer(
        address to,
        uint256 value
    ) public override whenNotPaused onlyProxy returns (bool) {
        super.transfer(to, value);
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 value
    ) public override whenNotPaused onlyProxy returns (bool) {
        if (isFrozen(_msgSender())) revert AccountFrozen(_msgSender());

        super.transferFrom(from, to, value);
        return true;
    }

    // ====================
    // UpgradeAuditor functions
    // ====================
    // @notice auditedImpl storage slot
    // keccak256(abi.encode(uint256(keccak256(bytes("AUDITED_IMPL"))) - 1)) & ~bytes32(uint256(0xff));
    bytes32 private constant auditedImpl =
        0x3b37ab6d30949955efc7d48c8e307e07fbeac94d91117e502bd889402f542100;

    function getAuditedImpl() public view returns (address impl) {
        assembly {
            impl := sload(auditedImpl)
        }
        return impl;
    }

    modifier isAuditedImpl(address _newImpl) {
        address auditedImplAddr = getAuditedImpl();

        if (auditedImplAddr != _newImpl) {
            revert NotAudited(_newImpl);
        }
        _;
    }

    // When upgrader is trying to upgrade without auditing, it will revert
    error NotAudited(address newImpl);

    function _authorizeUpgrade(
        address _newImplementation
    )
        internal
        override
        onlyProxy
        onlyRole(UPGRADER_ROLE)
        isAuditedImpl(_newImplementation)
    {}

    // @notice Update the audited implementation address
    // @dev Only accounts with the UPGRADE_AUDITOR_ROLE can call this function
    // @dev This function allows the upgrade auditor to set the address of the audited implementation contract.
    // @dev This function is not including Updating the implementation itself, only setting the audited address.
    function updateAuditedImpl(
        address _newImpl
    ) external onlyProxy onlyRole(UPGRADE_AUDITOR_ROLE) {
        assembly {
            sstore(auditedImpl, _newImpl)
        }
    }

    // ====================
    // EIP3009
    // ====================
    // keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH =
        0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267;

    // keccak256("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH =
        0xd099cc98ef71107a616c4f0f941f04c322d8e254fe26b3c6668db87aae413de8;

    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenNotPaused onlyProxy {
        // check time validity
        if (block.timestamp < validAfter || block.timestamp > validBefore) {
            revert AuthorizationExpired(
                validAfter,
                validBefore,
                block.timestamp
            );
        }

        AuthorizationStorage storage store = _getUsedNoncesStorage();
        // check nonce validity
        if (store.usedNonces[from][nonce]) {
            revert InvalidAuthorization(from, nonce);
        }

        // Verify Signature
        bytes32 structHash = keccak256(
            abi.encode(
                TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
                from,
                to,
                value,
                validAfter,
                validBefore,
                nonce
            )
        );

        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ecrecover(hash, v, r, s);

        if (signer != from) {
            revert InvalidSignature();
        }

        // Mark the nonce as used
        store.usedNonces[from][nonce] = true;
        emit AuthorizationUsed(from, nonce);

        _transfer(from, to, value);
    }

    error CallerIsNotRecipient();
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenNotPaused onlyProxy {
        // check if msg.sender is the recipient
        if (to != msg.sender) {
            revert CallerIsNotRecipient();
        }

        // check time validity
        if (block.timestamp < validAfter || block.timestamp > validBefore) {
            revert AuthorizationExpired(
                validAfter,
                validBefore,
                block.timestamp
            );
        }

        AuthorizationStorage storage store = _getUsedNoncesStorage();
        // check nonce validity
        if (store.usedNonces[from][nonce]) {
            revert InvalidAuthorization(from, nonce);
        }

        // Verify Signature
        bytes32 structHash = keccak256(
            abi.encode(
                RECEIVE_WITH_AUTHORIZATION_TYPEHASH,
                from,
                to,
                value,
                validAfter,
                validBefore,
                nonce
            )
        );

        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ecrecover(hash, v, r, s);

        if (signer != from) {
            revert InvalidSignature();
        }

        // Mark the nonce as used
        store.usedNonces[from][nonce] = true;
        emit AuthorizationUsed(from, nonce);

        _transfer(from, to, value);
    }

    // ====================
    // Events
    // ====================
    event Minted(address indexed to, uint256 amount);
    event VaultedWeight(uint256 vaultedWeight);
    event Burned(address indexed from, uint256 amount);
    event Frozen(address indexed account);
    event Unfrozen(address indexed account);
    event Wiped(address indexed account, uint256 amount);
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);
}
