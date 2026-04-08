#[starknet::contract]
mod VulnerableVault {
    use starknet::ContractAddress;
    use starknet::get_caller_address;

    #[storage]
    struct Storage {
        balances: LegacyMap<ContractAddress, u256>,
        owner: ContractAddress,
        total_deposits: u256,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
        let caller = get_caller_address();
        self.owner.write(caller);
    }

    #[external(v0)]
    fn deposit(ref self: ContractState, amount: u256) {
        let caller = get_caller_address();
        let current_balance = self.balances.read(caller);
        
        // Vulnerability: Unchecked arithmetic - potential overflow
        self.balances.write(caller, current_balance + amount);
        self.total_deposits.write(self.total_deposits.read() + amount);
    }

    #[external(v0)]
    fn withdraw(ref self: ContractState, amount: u256) {
        let caller = get_caller_address();
        let balance = self.balances.read(caller);
        
        assert(balance >= amount, 'Insufficient balance');
        
        // Vulnerability: Reentrancy - external call before state update
        self.transfer_tokens(caller, amount);
        self.balances.write(caller, balance - amount);
    }

    #[external(v0)]
    fn emergency_withdraw(ref self: ContractState) {
        // Vulnerability: Missing access control - no owner check
        let caller = get_caller_address();
        let total = self.total_deposits.read();
        self.transfer_tokens(caller, total);
        self.total_deposits.write(0);
    }

    #[external(v0)]
    fn update_owner(ref self: ContractState, new_owner: ContractAddress) {
        // Vulnerability: No zero address check
        // Vulnerability: No access control
        self.owner.write(new_owner);
    }

    #[external(v0)]
    fn batch_transfer(ref self: ContractState, recipients: Array<ContractAddress>, amounts: Array<u256>) {
        // Vulnerability: No array length validation
        let mut i = 0;
        loop {
            if i >= recipients.len() {
                break;
            }
            let recipient = *recipients.at(i);
            let amount = *amounts.at(i);
            self.transfer_tokens(recipient, amount);
            i += 1;
        }
    }

    fn transfer_tokens(ref self: ContractState, to: ContractAddress, amount: u256) {
        // Simulated token transfer
    }

    #[external(v0)]
    fn get_balance(self: @ContractState, account: ContractAddress) -> u256 {
        self.balances.read(account)
    }
}
