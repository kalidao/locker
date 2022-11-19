// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {Script} from "forge-std/Script.sol";

import {ERC1155B, LexLocker} from "src/LexLocker.sol";

/// @notice A very simple deployment script.
contract Deploy is Script {

  /// @notice The main script entrypoint.
  /// @return locker The deployed contract.
  function run() external returns (LexLocker locker) {
    vm.startBroadcast();
    locker = new LexLocker(ERC1155B(address(0xdead)));
    vm.stopBroadcast();
  }
}