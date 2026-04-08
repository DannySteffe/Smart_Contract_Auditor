# @version ^0.3.7

# Secure Vyper Contract with Best Practices

owner: public(address)
balances: public(HashMap[address, uint256])
total_supply: public(uint256)
paused: public(bool)

event Deposit:
    user: indexed(address)
    amount: uint256

event Withdrawal:
    user: indexed(address)
    amount: uint256

event OwnershipTransferred:
    previous_owner: indexed(address)
    new_owner: indexed(address)

event Paused:
    by: indexed(address)

event Unpaused:
    by: indexed(address)

@external
def __init__():
    self.owner = msg.sender
    self.total_supply = 0
    self.paused = False

@internal
def _only_owner():
    assert msg.sender == self.owner, "Caller is not the owner"

@external
@payable
def deposit():
    assert not self.paused, "Contract is paused"
    assert msg.value > 0, "Must send ETH"
    
    # Checks-effects-interactions: state changes before external calls
    self.balances[msg.sender] += msg.value
    self.total_supply += msg.value
    
    log Deposit(msg.sender, msg.value)

@external
def withdraw(amount: uint256):
    assert not self.paused, "Contract is paused"
    assert amount > 0, "Amount must be greater than 0"
    assert self.balances[msg.sender] >= amount, "Insufficient balance"
    
    # Checks-effects-interactions: Update state BEFORE external call
    self.balances[msg.sender] -= amount
    self.total_supply -= amount
    
    log Withdrawal(msg.sender, amount)
    
    # External call happens last
    send(msg.sender, amount)

@external
def transfer_ownership(new_owner: address):
    self._only_owner()
    
    # Zero address check
    assert new_owner != empty(address), "New owner cannot be zero address"
    
    previous_owner: address = self.owner
    self.owner = new_owner
    
    log OwnershipTransferred(previous_owner, new_owner)

@external
def pause():
    self._only_owner()
    assert not self.paused, "Already paused"
    self.paused = True
    log Paused(msg.sender)

@external
def unpause():
    self._only_owner()
    assert self.paused, "Not paused"
    self.paused = False
    log Unpaused(msg.sender)

@external
def emergency_withdraw():
    self._only_owner()
    send(msg.sender, self.balance)

@external
@view
def get_balance(account: address) -> uint256:
    return self.balances[account]

@external
@view
def is_paused() -> bool:
    return self.paused
