// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {MockERC20} from "@base/test/utils/mocks/MockERC20.sol";
import {MockERC721} from "@base/test/utils/mocks/MockERC721.sol";
import {MockERC1155} from "@base/test/utils/mocks/MockERC1155.sol";

import {ERC1155B, LexLocker} from "../src/LexLocker.sol";

import "@std/Test.sol";

contract LexLockerTest is Test {
    LexLocker internal locker;

    function setUp() public payable {
        locker = new LexLocker(ERC1155B(address(0xdead)));
    }

    function testDeposit() public payable {}
}
