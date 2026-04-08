# Smart Contract Test Samples

This folder contains test samples for all supported languages to verify the analyzer's detection capabilities.

## 📁 Files

### Cairo Contracts
- **cairo-vulnerable.cairo** - Contains multiple vulnerabilities
- **cairo-secure.cairo** - Follows security best practices

### Vyper Contracts
- **vyper-vulnerable.vy** - Contains multiple vulnerabilities
- **vyper-secure.vy** - Follows security best practices

### Solidity Contracts
- **solidity-vulnerable.sol** - Contains multiple vulnerabilities
- **solidity-secure.sol** - Follows security best practices

---

## 🚨 Vulnerable Contracts

### Cairo Vulnerable (`cairo-vulnerable.cairo`)
**Expected Vulnerabilities:**
- ❌ Reentrancy (withdraw function)
- ❌ Missing access control (emergency_withdraw, update_owner)
- ❌ Missing zero address check (update_owner)
- ❌ Unchecked arithmetic
- ❌ Array length validation missing

**Expected Score:** ~0-25/100 (Critical Risk)

### Vyper Vulnerable (`vyper-vulnerable.vy`)
**Expected Vulnerabilities:**
- ❌ Reentrancy (withdraw function)
- ❌ Missing access control (emergency_withdraw, set_owner)
- ❌ Missing zero address check (set_owner)
- ❌ Unchecked send return value
- ❌ Outdated compiler version (0.2.15)
- ❌ tx.origin authentication
- ❌ Integer overflow (older Vyper)

**Expected Score:** ~0-20/100 (Critical Risk)

### Solidity Vulnerable (`solidity-vulnerable.sol`)
**Expected Vulnerabilities:**
- ❌ Reentrancy (withdraw function)
- ❌ Unprotected ether withdrawal (withdrawAll)
- ❌ Unprotected selfdestruct (destroy)
- ❌ Missing access control (setOwner)
- ❌ Missing zero address check (setOwner)
- ❌ Integer overflow (Solidity 0.7.0)
- ❌ tx.origin authentication
- ❌ Array length validation missing

**Expected Score:** ~0-15/100 (Critical Risk)

---

## ✅ Secure Contracts

### Cairo Secure (`cairo-secure.cairo`)
**Security Features:**
- ✅ Checks-Effects-Interactions pattern
- ✅ Access control via `assert_only_owner()`
- ✅ Zero address validation
- ✅ Event emissions
- ✅ Pausable functionality
- ✅ Input validation
- ✅ No reentrancy vulnerabilities

**Expected Score:** ~75-90/100 (Low-Medium Risk)

### Vyper Secure (`vyper-secure.vy`)
**Security Features:**
- ✅ Checks-Effects-Interactions pattern
- ✅ Access control via `_only_owner()` helper
- ✅ Zero address validation
- ✅ Event emissions (logs)
- ✅ Pausable functionality
- ✅ Modern Vyper version (0.3.7+)
- ✅ No reentrancy vulnerabilities

**Expected Score:** ~75-90/100 (Low-Medium Risk)

### Solidity Secure (`solidity-secure.sol`)
**Security Features:**
- ✅ Checks-Effects-Interactions pattern
- ✅ Access control via `onlyOwner` modifier
- ✅ Zero address validation
- ✅ Event emissions
- ✅ Pausable functionality
- ✅ Modern Solidity version (0.8.20 - built-in overflow protection)
- ✅ No reentrancy vulnerabilities
- ✅ Uses msg.sender (not tx.origin)

**Expected Score:** ~80-95/100 (Low Risk)

---

## 🧪 How to Test

### Using the Web Interface
1. Start the development server: `npm run dev`
2. Navigate to http://localhost:3000/analyzer
3. Upload or paste one of the test contracts
4. Click "Start Analysis"
5. Compare results with expected vulnerabilities above

### Expected Results Summary

| Contract | Language | Expected Score | Expected Risk | Vulnerabilities |
|----------|----------|---------------|---------------|-----------------|
| cairo-vulnerable.cairo | Cairo | 0-25 | Critical | 6+ |
| cairo-secure.cairo | Cairo | 75-90 | Low-Medium | 0-2 |
| vyper-vulnerable.vy | Vyper | 0-20 | Critical | 7+ |
| vyper-secure.vy | Vyper | 75-90 | Low-Medium | 0-2 |
| solidity-vulnerable.sol | Solidity | 0-15 | Critical | 8+ |
| solidity-secure.sol | Solidity | 80-95 | Low | 0-1 |

---

## 📊 Verification Checklist

After running analysis, verify:

### For Vulnerable Contracts:
- [ ] Critical severity issues detected
- [ ] Reentrancy vulnerability flagged
- [ ] Missing access control detected
- [ ] Security score below 30
- [ ] Risk level shows "Critical"

### For Secure Contracts:
- [ ] Few or no vulnerabilities detected
- [ ] No critical issues
- [ ] Security score above 70
- [ ] Risk level shows "Low" or "Medium"

---

## 🔧 False Positive Testing

The secure contracts are specifically designed to test false positive reduction:
- Public user functions (deposit, withdraw) should NOT be flagged for missing access control
- Helper functions with access control should be recognized
- Zero address checks in various formats should be detected
- Proper CEI pattern should not trigger reentrancy warnings

If secure contracts show high vulnerability counts, review the pattern detection logic.
