// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {WrappedCryptEX} from "../src/WrappedCryptEX.sol";
import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {ERC20Capped} from "openzeppelin-contracts/contracts/token/ERC20/extensions/ERC20Capped.sol";
import {IAccessControl} from "openzeppelin-contracts/contracts/access/IAccessControl.sol";
import {Pausable} from "openzeppelin-contracts/contracts/utils/Pausable.sol";

contract MockToken is ERC20 {
    constructor() ERC20("Mock Token", "MOCK") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract WrappedCryptEXTest is Test {
    bytes32 internal constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    address internal admin = makeAddr("admin");
    address internal minter = makeAddr("minter");
    address internal pauser = makeAddr("pauser");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    uint256 internal alicePk = 0xA11CE;
    address internal aliceSigner;

    WrappedCryptEX internal token;
    MockToken internal mockToken;

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

    function setUp() public {
        aliceSigner = vm.addr(alicePk);
        token = new WrappedCryptEX("Wrapped CryptEX", "wCRX", admin, minter, pauser);
        mockToken = new MockToken();
    }

    function test_MetadataRolesAndSupplyCap() public view {
        assertEq(token.name(), "Wrapped CryptEX");
        assertEq(token.symbol(), "wCRX");
        assertEq(token.decimals(), 18);
        assertEq(token.totalSupply(), 0);
        assertEq(token.cap(), 1_000_000_000 ether);
        assertEq(token.defaultAdminDelay(), 2 days);
        assertTrue(token.hasRole(token.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(token.hasRole(token.MINTER_ROLE(), minter));
        assertTrue(token.hasRole(token.PAUSER_ROLE(), admin));
        assertTrue(token.hasRole(token.PAUSER_ROLE(), pauser));
    }

    function test_OnlyMinterCanMint() public {
        bytes32 depositId = keccak256("deposit-1");
        bytes32 nativeTxId = keccak256("native-1");

        vm.prank(minter);
        token.mintFromBridge(alice, 125 ether, depositId, nativeTxId, "native-sender");

        assertEq(token.balanceOf(alice), 125 ether);
        assertEq(token.totalSupply(), 125 ether);
        assertTrue(token.isProcessedDeposit(depositId));

        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, bob, token.MINTER_ROLE())
        );
        vm.prank(bob);
        token.mintFromBridge(bob, 1 ether, keccak256("deposit-2"), keccak256("native-2"), "native-sender");
    }

    function test_MintRejectsDuplicateDepositId() public {
        bytes32 depositId = keccak256("deposit-duplicate");
        bytes32 nativeTxId = keccak256("native-duplicate");

        vm.startPrank(minter);
        token.mintFromBridge(alice, 10 ether, depositId, nativeTxId, "native-sender");
        vm.expectRevert(abi.encodeWithSelector(WrappedCryptEX.DepositAlreadyProcessed.selector, depositId));
        token.mintFromBridge(alice, 10 ether, depositId, keccak256("native-duplicate-2"), "native-sender");
        vm.stopPrank();
    }

    function test_MintRejectsCapOverflow() public {
        vm.startPrank(minter);
        token.mintFromBridge(alice, token.cap(), keccak256("deposit-cap"), keccak256("native-cap"), "native-sender");
        uint256 overflowAmount = token.BRIDGE_UNIT();
        vm.expectRevert(
            abi.encodeWithSelector(ERC20Capped.ERC20ExceededCap.selector, token.cap() + overflowAmount, token.cap())
        );
        token.mintFromBridge(
            alice, overflowAmount, keccak256("deposit-over"), keccak256("native-over"), "native-sender"
        );
        vm.stopPrank();
    }

    function test_MintRejectsNonIntegralBridgeUnits() public {
        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(WrappedCryptEX.NonIntegralBridgeUnit.selector, 1));
        token.mintFromBridge(alice, 1, keccak256("deposit-fractional"), keccak256("native-fractional"), "");
    }

    function test_RequestRedemptionBurnsAndEmits() public {
        bytes32 depositId = keccak256("deposit-redemption");
        bytes32 nativeTxId = keccak256("native-redemption");
        uint256 amount = 40 ether;

        vm.prank(minter);
        token.mintFromBridge(alice, amount, depositId, nativeTxId, "native-sender");

        bytes32 expectedId = keccak256(
            abi.encode(block.chainid, address(token), alice, alice, 10 ether, 1, "AAECAwQFBgcICQoLDA0ODxAREhM=")
        );

        vm.expectEmit(true, true, true, true);
        emit RedemptionRequested(expectedId, alice, alice, "AAECAwQFBgcICQoLDA0ODxAREhM=", 10 ether, 1);

        vm.prank(alice);
        bytes32 redemptionId = token.requestRedemption(10 ether, "AAECAwQFBgcICQoLDA0ODxAREhM=");

        assertEq(redemptionId, expectedId);
        assertEq(token.balanceOf(alice), amount - 10 ether);
        assertEq(token.totalSupply(), amount - 10 ether);
        assertEq(token.redemptionNonce(), 1);
    }

    function test_RequestRedemptionFromUsesAllowance() public {
        vm.prank(minter);
        token.mintFromBridge(alice, 50 ether, keccak256("deposit-burnfrom"), keccak256("native-burnfrom"), "");

        vm.prank(alice);
        token.approve(bob, 12 ether);

        vm.prank(bob);
        token.requestRedemptionFrom(alice, 12 ether, "AAECAwQFBgcICQoLDA0ODxAREhM=");

        assertEq(token.balanceOf(alice), 38 ether);
        assertEq(token.allowance(alice, bob), 0);
        assertEq(token.redemptionNonce(), 1);
    }

    function test_TransferRejectsNonIntegralBridgeUnits() public {
        vm.prank(minter);
        token.mintFromBridge(alice, 10 ether, keccak256("deposit-transfer"), keccak256("native-transfer"), "");

        vm.expectRevert(abi.encodeWithSelector(WrappedCryptEX.NonIntegralBridgeUnit.selector, 1));
        vm.prank(alice);
        token.transfer(bob, 1);
    }

    function test_PauseBlocksTransferMintAndRedemption() public {
        vm.prank(minter);
        token.mintFromBridge(alice, 20 ether, keccak256("deposit-pause"), keccak256("native-pause"), "");

        vm.prank(pauser);
        token.pause();

        vm.expectRevert(Pausable.EnforcedPause.selector);
        vm.prank(alice);
        bool ignored;
        ignored = token.transfer(bob, 1 ether);
        ignored;

        vm.expectRevert(Pausable.EnforcedPause.selector);
        vm.prank(minter);
        token.mintFromBridge(alice, 1 ether, keccak256("deposit-pause-2"), keccak256("native-pause-2"), "");

        vm.expectRevert(Pausable.EnforcedPause.selector);
        vm.prank(alice);
        token.requestRedemption(1 ether, "AAECAwQFBgcICQoLDA0ODxAREhM=");
    }

    function test_PermitApprovesAllowance() public {
        vm.prank(minter);
        token.mintFromBridge(aliceSigner, 5 ether, keccak256("deposit-permit"), keccak256("native-permit"), "");

        uint256 deadline = block.timestamp + 1 days;
        uint256 value = 3 ether;
        uint256 nonce = token.nonces(aliceSigner);

        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, aliceSigner, bob, value, nonce, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, digest);

        vm.prank(bob);
        token.permit(aliceSigner, bob, value, deadline, v, r, s);

        assertEq(token.allowance(aliceSigner, bob), value);
    }

    function test_AdminCanRescueForeignTokenButNotWrappedToken() public {
        mockToken.mint(address(token), 100 ether);

        vm.prank(admin);
        token.rescueERC20(address(mockToken), bob, 25 ether);
        assertEq(mockToken.balanceOf(bob), 25 ether);

        vm.prank(admin);
        vm.expectRevert(WrappedCryptEX.CannotRescueWrappedToken.selector);
        token.rescueERC20(address(token), bob, 1 ether);
    }
}
