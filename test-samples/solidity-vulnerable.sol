// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

// Vulnerable Solidity Contract

contract VulnerableBank {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    
    constructor() {
        owner = msg.sender;
    }
    
    function deposit() public payable {
        // Vulnerability: Unchecked arithmetic in Solidity < 0.8.0
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }
    
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Vulnerability: Reentrancy - external call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount;
    }
    
    function withdrawAll() public {
        // Vulnerability: Missing access control - anyone can drain
        payable(msg.sender).transfer(address(this).balance);
    }
    
    function destroy() public {
        // Vulnerability: Unprotected selfdestruct
        selfdestruct(payable(msg.sender));
    }
    
    function setOwner(address newOwner) public {
        // Vulnerability: No access control
        // Vulnerability: No zero address check
        owner = newOwner;
    }
    
    function batchTransfer(address[] memory recipients, uint256[] memory amounts) public {
        // Vulnerability: No array length validation
        for (uint i = 0; i < recipients.length; i++) {
            payable(recipients[i]).transfer(amounts[i]);
        }
    }
    
    function authWithTxOrigin() public {
        // Vulnerability: tx.origin authentication
        require(tx.origin == owner, "Not owner");
    }
    
    function getBalance() public view returns (uint256) {
        return balances[msg.sender];
    }
}
