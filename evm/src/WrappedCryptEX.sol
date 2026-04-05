// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {
    AccessControlDefaultAdminRules
} from "openzeppelin-contracts/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {ERC20Capped} from "openzeppelin-contracts/contracts/token/ERC20/extensions/ERC20Capped.sol";
import {ERC20Permit} from "openzeppelin-contracts/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {ERC20Pausable} from "openzeppelin-contracts/contracts/token/ERC20/extensions/ERC20Pausable.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title WrappedCryptEX
/// @notice Mainnet-ready wrapped CryptEX ERC-20 for the initial custodial bridge.
/// @dev Minting is bridge-operator controlled, redemptions burn onchain and emit
///      explicit events for the native CryptEX release workflow.
contract WrappedCryptEX is ERC20, ERC20Capped, ERC20Permit, ERC20Pausable, AccessControlDefaultAdminRules {
    using SafeERC20 for IERC20;

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    uint256 public constant NATIVE_SUPPLY_CAP = 1_000_000_000 ether;
    uint256 public constant BRIDGE_UNIT = 10_000_000_000;
    uint256 public constant MAX_NATIVE_REFERENCE_LENGTH = 128;
    uint48 public constant DEFAULT_ADMIN_TRANSFER_DELAY = 2 days;

    error ZeroAddress();
    error ZeroAmount();
    error EmptyTokenMetadata();
    error InvalidBridgeDepositId();
    error InvalidNativeTxId();
    error DepositAlreadyProcessed(bytes32 depositId);
    error EmptyNativeDestination();
    error NativeReferenceTooLong(uint256 length);
    error CannotRescueWrappedToken();
    error NonIntegralBridgeUnit(uint256 amount);

    event BridgeMintRecorded(
        bytes32 indexed depositId,
        bytes32 indexed nativeTxId,
        address indexed recipient,
        uint256 amount,
        string nativeSender,
        address operator
    );

    event RedemptionRequested(
        bytes32 indexed redemptionId,
        address indexed account,
        address indexed operator,
        string nativeDestination,
        uint256 amount,
        uint256 nonce
    );

    mapping(bytes32 depositId => bool processed) private _processedDeposits;
    uint256 public redemptionNonce;

    constructor(
        string memory tokenName,
        string memory tokenSymbol,
        address initialAdmin,
        address initialMinter,
        address initialPauser
    )
        ERC20(tokenName, tokenSymbol)
        ERC20Permit(tokenName)
        ERC20Capped(NATIVE_SUPPLY_CAP)
        AccessControlDefaultAdminRules(DEFAULT_ADMIN_TRANSFER_DELAY, initialAdmin)
    {
        if (bytes(tokenName).length == 0 || bytes(tokenSymbol).length == 0) {
            revert EmptyTokenMetadata();
        }

        _grantRole(PAUSER_ROLE, initialAdmin);

        if (initialMinter != address(0)) {
            _grantRole(MINTER_ROLE, initialMinter);
        }

        if (initialPauser != address(0) && initialPauser != initialAdmin) {
            _grantRole(PAUSER_ROLE, initialPauser);
        }
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function mintFromBridge(
        address to,
        uint256 amount,
        bytes32 depositId,
        bytes32 nativeTxId,
        string calldata nativeSender
    ) external onlyRole(MINTER_ROLE) whenNotPaused {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        if (amount % BRIDGE_UNIT != 0) revert NonIntegralBridgeUnit(amount);
        if (depositId == bytes32(0)) revert InvalidBridgeDepositId();
        if (nativeTxId == bytes32(0)) revert InvalidNativeTxId();
        _validateReference(nativeSender, true);

        if (_processedDeposits[depositId]) {
            revert DepositAlreadyProcessed(depositId);
        }
        _processedDeposits[depositId] = true;

        _mint(to, amount);

        emit BridgeMintRecorded(depositId, nativeTxId, to, amount, nativeSender, _msgSender());
    }

    function requestRedemption(uint256 amount, string calldata nativeDestination)
        external
        whenNotPaused
        returns (bytes32 redemptionId)
    {
        return _requestRedemption(_msgSender(), _msgSender(), amount, nativeDestination);
    }

    function requestRedemptionFrom(address account, uint256 amount, string calldata nativeDestination)
        external
        whenNotPaused
        returns (bytes32 redemptionId)
    {
        _spendAllowance(account, _msgSender(), amount);
        return _requestRedemption(account, _msgSender(), amount, nativeDestination);
    }

    function rescueERC20(address token, address to, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (token == address(this)) revert CannotRescueWrappedToken();
        if (to == address(0)) revert ZeroAddress();
        IERC20(token).safeTransfer(to, amount);
    }

    function isProcessedDeposit(bytes32 depositId) external view returns (bool) {
        return _processedDeposits[depositId];
    }

    function remainingMintCapacity() external view returns (uint256) {
        return cap() - totalSupply();
    }

    function supportsInterface(bytes4 interfaceId) public view override(AccessControlDefaultAdminRules) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function _requestRedemption(address account, address operator, uint256 amount, string calldata nativeDestination)
        internal
        returns (bytes32 redemptionId)
    {
        if (amount == 0) revert ZeroAmount();
        if (amount % BRIDGE_UNIT != 0) revert NonIntegralBridgeUnit(amount);

        uint256 nextNonce = redemptionNonce + 1;
        redemptionNonce = nextNonce;

        _validateReference(nativeDestination, false);
        _burn(account, amount);

        redemptionId = keccak256(
            abi.encode(block.chainid, address(this), account, operator, amount, nextNonce, nativeDestination)
        );

        emit RedemptionRequested(redemptionId, account, operator, nativeDestination, amount, nextNonce);
    }

    function _validateReference(string calldata value, bool allowEmpty) internal pure {
        uint256 length = bytes(value).length;
        if (!allowEmpty && length == 0) revert EmptyNativeDestination();
        if (length > MAX_NATIVE_REFERENCE_LENGTH) revert NativeReferenceTooLong(length);
    }

    function _update(address from, address to, uint256 value) internal override(ERC20, ERC20Capped, ERC20Pausable) {
        if (value != 0 && value % BRIDGE_UNIT != 0) {
            revert NonIntegralBridgeUnit(value);
        }
        super._update(from, to, value);
    }
}
