// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {WrappedCryptEX} from "../src/WrappedCryptEX.sol";

contract DeployWrappedCryptEXScript is Script {
    function run() external returns (WrappedCryptEX token) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address admin = vm.envAddress("WRAPPED_CRX_ADMIN");
        address minter = vm.envOr("WRAPPED_CRX_MINTER", address(0));
        address pauser = vm.envOr("WRAPPED_CRX_PAUSER", admin);
        string memory tokenName = vm.envOr("WRAPPED_CRX_NAME", string("Wrapped CryptEX"));
        string memory tokenSymbol = vm.envOr("WRAPPED_CRX_SYMBOL", string("wCRX"));

        vm.startBroadcast(deployerPrivateKey);
        token = new WrappedCryptEX(tokenName, tokenSymbol, admin, minter, pauser);
        vm.stopBroadcast();

        console2.log("WrappedCryptEX deployed at", address(token));
        console2.log("Admin", admin);
        console2.log("Minter", minter);
        console2.log("Pauser", pauser);
    }
}
