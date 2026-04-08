// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Secure Solidity Contract with Best Practices

contract SecureBank {
    address private owner;
    mapping(address => uint256) private balances;
    uint256 private totalDeposits;
    bool private paused;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event Paused(address indexed by);
    event Unpaused(address indexed by);
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Caller is not the owner");
        _;
    }
    
    modifier whenNotPaused() {
        require(!paused, "Contract is paused");
        _;
    }
    
    constructor() {
        owner = msg.sender;
        paused = false;
    }
    
    function deposit() external payable whenNotPaused {
        require(msg.value > 0, "Must send ETH");
        
        // Solidity 0.8.0+ has built-in overflow protection
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        
        emit Deposit(msg.sender, msg.value);
    }
    
    function withdraw(uint256 amount) external whenNotPaused {
        require(amount > 0, "Amount must be greater than 0");
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Checks-Effects-Interactions: Update state BEFORE external call
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
        
        emit Withdrawal(msg.sender, amount);
        
        // External call happens last
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
    
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        
        address previousOwner = owner;
        owner = newOwner;
        
        emit OwnershipTransferred(previousOwner, newOwner);
    }
    
    function pause() external onlyOwner {
        require(!paused, "Already paused");
        paused = true;
        emit Paused(msg.sender);
    }
    
    function unpause() external onlyOwner {
        require(paused, "Not paused");
        paused = false;
        emit Unpaused(msg.sender);
    }
    
    function emergencyWithdraw() external onlyOwner {
        uint256 balance = address(this).balance;
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
    }
    
    function getBalance(address account) external view returns (uint256) {
        return balances[account];
    }
    
    function getTotalDeposits() external view returns (uint256) {
        return totalDeposits;
    }
    
    function getOwner() external view returns (address) {
        return owner;
    }
    
    function isPaused() external view returns (bool) {
        return paused;
    }
}
