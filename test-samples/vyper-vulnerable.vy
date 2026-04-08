# @version ^0.2.15

# Vulnerable Vyper Contract

owner: public(address)
balances: public(HashMap[address, uint256])
total_supply: public(uint256)

@external
def __init__():
    self.owner = msg.sender
    self.total_supply = 0

@external
def deposit() -> bool:
    # Vulnerability: Unchecked arithmetic in older Vyper
    self.balances[msg.sender] += msg.value
    self.total_supply += msg.value
    return True

@external
def withdraw(amount: uint256):
    assert self.balances[msg.sender] >= amount, "Insufficient balance"
    
    # Vulnerability: Reentrancy - external call before state update
    send(msg.sender, amount)
    self.balances[msg.sender] -= amount

@external
def emergency_withdraw():
    # Vulnerability: Missing access control - anyone can call
    send(msg.sender, self.balance)

@external
def set_owner(new_owner: address):
    # Vulnerability: No access control
    # Vulnerability: No zero address check
    self.owner = new_owner

@external
def batch_transfer(recipients: address[10], amounts: uint256[10]):
    # Vulnerability: No validation, unchecked sends
    for i in range(10):
        send(recipients[i], amounts[i])

@external
def withdraw_to(recipient: address, amount: uint256):
    # Vulnerability: tx.origin usage
    assert tx.origin == self.owner, "Not owner"
    send(recipient, amount)

@external
@view
def get_balance(account: address) -> uint256:
    return self.balances[account]
