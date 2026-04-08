#[starknet::contract]
mod SecureVault {
    use starknet::ContractAddress;
    use starknet::get_caller_address;
    use starknet::contract_address_const;

    #[storage]
    struct Storage {
        balances: LegacyMap<ContractAddress, u256>,
        owner: ContractAddress,
        total_deposits: u256,
        paused: bool,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        Deposit: Deposit,
        Withdrawal: Withdrawal,
        OwnershipTransferred: OwnershipTransferred,
        Paused: Paused,
        Unpaused: Unpaused,
    }

    #[derive(Drop, starknet::Event)]
    struct Deposit {
        user: ContractAddress,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct Withdrawal {
        user: ContractAddress,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct OwnershipTransferred {
        previous_owner: ContractAddress,
        new_owner: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct Paused {
        by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct Unpaused {
        by: ContractAddress,
    }

    #[constructor]
    fn constructor(ref self: ContractState, initial_owner: ContractAddress) {
        // Zero address check
        assert(!initial_owner.is_zero(), 'Owner cannot be zero address');
        self.owner.write(initial_owner);
        self.paused.write(false);
    }

    #[external(v0)]
    fn deposit(ref self: ContractState, amount: u256) {
        // Check if paused
        assert(!self.paused.read(), 'Contract is paused');
        
        // Validate amount
        assert(amount > 0, 'Amount must be greater than 0');
        
        let caller = get_caller_address();
        let current_balance = self.balances.read(caller);
        
        // Checks-effects-interactions: Update state before external calls
        let new_balance = current_balance + amount;
        self.balances.write(caller, new_balance);
        
        let new_total = self.total_deposits.read() + amount;
        self.total_deposits.write(new_total);
        
        // Emit event
        self.emit(Deposit { user: caller, amount: amount });
    }

    #[external(v0)]
    fn withdraw(ref self: ContractState, amount: u256) {
        // Check if paused
        assert(!self.paused.read(), 'Contract is paused');
        
        // Validate amount
        assert(amount > 0, 'Amount must be greater than 0');
        
        let caller = get_caller_address();
        let balance = self.balances.read(caller);
        
        // Check sufficient balance
        assert(balance >= amount, 'Insufficient balance');
        
        // Checks-effects-interactions: Update state BEFORE external call
        let new_balance = balance - amount;
        self.balances.write(caller, new_balance);
        
        let new_total = self.total_deposits.read() - amount;
        self.total_deposits.write(new_total);
        
        // Emit event before transfer
        self.emit(Withdrawal { user: caller, amount: amount });
        
        // External call happens last (after state updates)
        self.transfer_tokens(caller, amount);
    }

    #[external(v0)]
    fn transfer_ownership(ref self: ContractState, new_owner: ContractAddress) {
        // Access control - only owner
        self.assert_only_owner();
        
        // Zero address check
        assert(!new_owner.is_zero(), 'New owner cannot be zero');
        
        let previous_owner = self.owner.read();
        self.owner.write(new_owner);
        
        // Emit event
        self.emit(OwnershipTransferred { previous_owner, new_owner });
    }

    #[external(v0)]
    fn pause(ref self: ContractState) {
        // Access control - only owner
        self.assert_only_owner();
        
        assert(!self.paused.read(), 'Already paused');
        self.paused.write(true);
        
        let caller = get_caller_address();
        self.emit(Paused { by: caller });
    }

    #[external(v0)]
    fn unpause(ref self: ContractState) {
        // Access control - only owner
        self.assert_only_owner();
        
        assert(self.paused.read(), 'Not paused');
        self.paused.write(false);
        
        let caller = get_caller_address();
        self.emit(Unpaused { by: caller });
    }

    #[external(v0)]
    fn get_balance(self: @ContractState, account: ContractAddress) -> u256 {
        self.balances.read(account)
    }

    #[external(v0)]
    fn get_total_deposits(self: @ContractState) -> u256 {
        self.total_deposits.read()
    }

    #[external(v0)]
    fn get_owner(self: @ContractState) -> ContractAddress {
        self.owner.read()
    }

    #[external(v0)]
    fn is_paused(self: @ContractState) -> bool {
        self.paused.read()
    }

    #[generate_trait]
    impl InternalFunctions of InternalFunctionsTrait {
        fn assert_only_owner(self: @ContractState) {
            let caller = get_caller_address();
            let owner = self.owner.read();
            assert(caller == owner, 'Caller is not the owner');
        }

        fn transfer_tokens(ref self: ContractState, to: ContractAddress, amount: u256) {
            // Token transfer implementation
        }
    }
}
