// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Small training fixture for Foundry tests; not production audited.
contract TrainingVault {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public totalDeposits;
    bool private entered;

    error NotOwner();
    error InsufficientBalance();
    error TransferFailed();
    error ReentrantCall();
    error ZeroAddress();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier nonReentrant() {
        if (entered) revert ReentrantCall();
        entered = true;
        _;
        entered = false;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    function withdraw(uint256 amount) external nonReentrant {
        if (balances[msg.sender] < amount) revert InsufficientBalance();
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    function setOwner(address nextOwner) external onlyOwner {
        if (nextOwner == address(0)) revert ZeroAddress();
        owner = nextOwner;
    }
}
