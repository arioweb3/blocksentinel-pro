// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import "../src/TrainingVault.sol";

contract TrainingVaultTest is Test {
    TrainingVault internal vault;
    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);

    function setUp() public {
        vault = new TrainingVault();
        vm.deal(alice, 10 ether);
        vm.deal(bob, 10 ether);
    }

    function testDepositUpdatesAccounting() public {
        vm.prank(alice);
        vault.deposit{value: 2 ether}();
        assertEq(vault.balances(alice), 2 ether);
        assertEq(vault.totalDeposits(), 2 ether);
        assertEq(address(vault).balance, 2 ether);
    }

    function testWithdrawUpdatesAccounting() public {
        vm.startPrank(alice);
        vault.deposit{value: 3 ether}();
        vault.withdraw(1 ether);
        vm.stopPrank();
        assertEq(vault.balances(alice), 2 ether);
        assertEq(vault.totalDeposits(), 2 ether);
        assertEq(address(vault).balance, 2 ether);
    }

    function testCannotWithdrawMoreThanBalance() public {
        vm.prank(alice);
        vm.expectRevert(TrainingVault.InsufficientBalance.selector);
        vault.withdraw(1 ether);
    }

    function testOnlyOwnerCanChangeOwner() public {
        vm.prank(alice);
        vm.expectRevert(TrainingVault.NotOwner.selector);
        vault.setOwner(bob);
        vault.setOwner(bob);
        assertEq(vault.owner(), bob);
    }

    function testFuzzDepositAndWithdraw(uint96 amount) public {
        vm.assume(amount > 0 && amount <= 10 ether);
        vm.deal(alice, uint256(amount));
        vm.startPrank(alice);
        vault.deposit{value: amount}();
        vault.withdraw(amount);
        vm.stopPrank();
        assertEq(vault.balances(alice), 0);
        assertEq(vault.totalDeposits(), 0);
        assertEq(address(vault).balance, 0);
    }

    function invariant_totalDepositsEqualsVaultBalance() public view {
        assertEq(vault.totalDeposits(), address(vault).balance);
    }
}
