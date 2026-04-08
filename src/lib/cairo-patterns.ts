// Cairo-specific Vulnerability Patterns

export interface CairoVulnerabilityPattern {
  id: string;
  name: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  description: string;
  pattern: RegExp;
  swcId?: string;
  csrId?: string;
  detector: (code: string) => boolean;
}

export const CAIRO_VULNERABILITY_PATTERNS: CairoVulnerabilityPattern[] = [
  {
    id: 'cairo-reentrancy',
    name: 'Potential Reentrancy Vulnerability',
    severity: 'Critical',
    description: 'External call detected before state changes. Follow checks-effects-interactions pattern.',
    pattern: /call_contract|library_call/,
    swcId: 'SWC-107',
    csrId: 'CSR-001',
    detector: (code: string): boolean => {
      const lines = code.split('\n');
      let inFunction = false;
      let hasExternalCall = false;
      let hasStateChange = false;

      for (const line of lines) {
        if (/fn\s+\w+/.test(line)) {
          inFunction = true;
          hasExternalCall = false;
          hasStateChange = false;
        }

        if (inFunction) {
          if (/call_contract|library_call/.test(line)) {
            hasExternalCall = true;
          }
          if (hasExternalCall && /\.write\(/.test(line)) {
            hasStateChange = true;
            return true;
          }
        }
      }
      return false;
    }
  },
  {
    id: 'cairo-unchecked-call',
    name: 'Unchecked External Call',
    severity: 'High',
    description: 'External contract call should be wrapped in error handling.',
    pattern: /call_contract|library_call/,
    csrId: 'CSR-002',
    detector: (code: string): boolean => {
      const lines = code.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/call_contract|library_call/.test(line)) {
          // Check if wrapped in match or has error handling
          let hasErrorHandling = false;
          for (let j = Math.max(0, i - 3); j <= Math.min(i + 3, lines.length - 1); j++) {
            if (/match\s+|\.unwrap\(|\.expect\(|assert|panic/.test(lines[j])) {
              hasErrorHandling = true;
              break;
            }
          }
          if (!hasErrorHandling) return true;
        }
      }
      return false;
    }
  },
  {
    id: 'cairo-integer-overflow',
    name: 'Potential Integer Overflow',
    severity: 'High',
    description: 'Arithmetic operations on felt252 can overflow. Use checked arithmetic or u256.',
    csrId: 'CSR-003',
    pattern: /felt252.*[\+\-\*]/,
    detector: (code: string): boolean => {
      // Check for unchecked arithmetic on felt252
      const lines = code.split('\n');
      for (const line of lines) {
        if (/:\s*felt252/.test(line) && /[\+\-\*]/.test(line)) {
          // Check if using checked operations
          if (!/checked_add|checked_sub|checked_mul/.test(line)) {
            return true;
          }
        }
      }
      return false;
    }
  },
  {
    id: 'cairo-missing-access-control',
    name: 'Missing Access Control',
    severity: 'Critical',
    description: 'External function lacks access control. Add ownership or permission checks.',
    pattern: /#\[external\(v0\)\]/,
    csrId: 'CSR-004',
    detector: (code: string): boolean => {
      const lines = code.split('\n');
      
      // Public user functions that should be accessible to everyone (not privileged)
      const publicUserFunctions = ['deposit', 'withdraw', 'transfer', 'approve', 'stake', 'unstake', 'claim', 'get_', 'is_'];
      
      for (let i = 0; i < lines.length; i++) {
        if (/#\[external/.test(lines[i])) {
          // Look ahead for function definition
          let j = i + 1;
          while (j < lines.length && !lines[j].trim()) j++;
          
          // Only check privileged functions (ownership, admin, emergency functions)
          if (j < lines.length && /fn\s+(transfer_ownership|set_owner|update_owner|emergency|pause|unpause|mint|burn|set_\w+|update_\w+)/.test(lines[j])) {
            const funcLine = lines[j];
            
            // Skip if it's a normal user function that matches our pattern
            let isPublicUserFunc = false;
            for (const publicFunc of publicUserFunctions) {
              if (new RegExp(`fn\\s+\\w*${publicFunc}`).test(funcLine)) {
                isPublicUserFunc = true;
                break;
              }
            }
            
            if (isPublicUserFunc) continue;
            
            // Check if there's access control (expanded patterns)
            let foundAccessControl = false;
            for (let k = j; k < Math.min(j + 20, lines.length); k++) {
              // Recognize various access control patterns
              if (/assert_only_owner|only_owner|assert.*owner.*==|assert.*caller.*==.*owner|Ownable::|assert.*get_caller_address\(\)\s*==|self\.assert_only/.test(lines[k])) {
                foundAccessControl = true;
                break;
              }
            }
            if (!foundAccessControl) return true;
          }
        }
      }
      return false;
    }
  },
  {
    id: 'cairo-zero-address-check',
    name: 'Missing Zero Address Check',
    severity: 'Medium',
    description: 'ContractAddress parameter should be validated against zero address.',
    pattern: /:\s*ContractAddress/,
    csrId: 'CSR-005',
    detector: (code: string): boolean => {
      const lines = code.split('\n');
      
      // Functions where zero address checks are critical
      const criticalFunctions = ['transfer_ownership', 'set_owner', 'update_owner', 'new_owner', 'recipient', 'to'];
      
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        
        // Skip non-function lines (imports, storage fields, event fields, struct fields)
        if (/use\s+|struct\s+Storage|struct\s+\w+\s*{|^\s*\w+:\s*ContractAddress,/.test(line)) {
          continue;
        }
        
        // Only check function parameters with ContractAddress
        if (/fn\s+\w+.*\(.*:\s*ContractAddress/.test(line)) {
          // Check if this is a critical function parameter
          let isCriticalParam = false;
          for (const critFunc of criticalFunctions) {
            if (new RegExp(critFunc, 'i').test(line)) {
              isCriticalParam = true;
              break;
            }
          }
          
          if (!isCriticalParam) continue;
          
          // Check if there's a zero address check (expanded patterns and more lines)
          let hasZeroCheck = false;
          for (let k = i; k < Math.min(i + 20, lines.length); k++) {
            // Recognize various zero address check patterns
            if (/assert\s*\(!.*\.is_zero\(\)|assert.*\.is_non_zero\(\)|assert.*!=.*zero_address|is_zero\(\).*false|!.*\.is_zero/.test(lines[k])) {
              hasZeroCheck = true;
              break;
            }
          }
          if (!hasZeroCheck) return true;
        }
      }
      return false;
    }
  },
  {
    id: 'cairo-timestamp-dependency',
    name: 'Timestamp Dependence',
    severity: 'Medium',
    description: 'Using block timestamp for critical logic can be manipulated.',
    pattern: /get_block_timestamp/,
    swcId: 'SWC-116',
    csrId: 'CSR-006',
    detector: (code: string): boolean => {
      return /get_block_timestamp/.test(code) && /(if|assert).*get_block_timestamp/.test(code);
    }
  },
  {
    id: 'cairo-unused-return',
    name: 'Unused Return Value',
    severity: 'Medium',
    description: 'Function return value is ignored. This may hide errors.',
    pattern: /call_contract|library_call/,
    csrId: 'CSR-008',
    detector: (code: string): boolean => {
      const lines = code.split('\n');
      for (const line of lines) {
        if (/(call_contract|library_call)\(/.test(line)) {
          // Check if return value is assigned
          if (!/let\s+\w+\s*=.*(?:call_contract|library_call)/.test(line)) {
            return true;
          }
        }
      }
      return false;
    }
  },
  {
    id: 'cairo-unsafe-felt-conversion',
    name: 'Unsafe felt252 Conversion',
    severity: 'High',
    description: 'Converting between felt252 and other types without validation can be dangerous.',
    pattern: /\.into\(\)|\.try_into\(\)/,
    csrId: 'CSR-003',
    detector: (code: string): boolean => {
      const lines = code.split('\n');
      for (const line of lines) {
        if (/\.into\(\)/.test(line) && !/\.try_into\(\)/.test(line)) {
          // Check if converting felt252
          if (/felt252/.test(line)) {
            return true;
          }
        }
      }
      return false;
    }
  },
  {
    id: 'cairo-missing-event',
    name: 'Missing Event Emission',
    severity: 'Low',
    description: 'Critical state changes should emit events for transparency.',
    pattern: /#\[external.*fn\s+(transfer|mint|burn|withdraw)/,
    csrId: 'CSR-014',
    detector: (code: string): boolean => {
      const lines = code.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (/#\[external/.test(lines[i])) {
          let j = i + 1;
          while (j < lines.length && !lines[j].trim()) j++;
          
          if (j < lines.length && /fn\s+(transfer|mint|burn|withdraw|set_|update_)/.test(lines[j])) {
            // Check if event is emitted
            let hasEvent = false;
            for (let k = j; k < Math.min(j + 25, lines.length); k++) {
              if (/\.emit\(|self\.emit_event/.test(lines[k])) {
                hasEvent = true;
                break;
              }
            }
            if (!hasEvent) return true;
          }
        }
      }
      return false;
    }
  },
  {
    id: 'cairo-storage-collision',
    name: 'Potential Storage Collision',
    severity: 'High',
    description: 'Storage variables should use unique keys to avoid collisions.',
    pattern: /@storage/,
    csrId: 'CSR-007',
    detector: (code: string): boolean => {
      const storageVars: string[] = [];
      const lines = code.split('\n');
      
      for (const line of lines) {
        const match = line.match(/(\w+):\s*LegacyMap|(\w+):\s*Map/);
        if (match) {
          const varName = match[1] || match[2];
          if (storageVars.includes(varName)) {
            return true; // Duplicate storage variable
          }
          storageVars.push(varName);
        }
      }
      return false;
    }
  },
  {
    id: 'cairo-unvalidated-input',
    name: 'Unvalidated Input Parameters',
    severity: 'Medium',
    description: 'Input parameters should be validated before use.',
    pattern: /fn\s+\w+.*\(/,
    csrId: 'CSR-010',
    detector: (code: string): boolean => {
      const lines = code.split('\n');
      
      // Functions that typically have built-in validation through balance checks
      const autoValidatedFunctions = ['deposit', 'withdraw', 'transfer', 'get_', 'is_', 'view'];
      
      for (let i = 0; i < lines.length; i++) {
        if (/#\[external/.test(lines[i])) {
          let j = i + 1;
          while (j < lines.length && !lines[j].trim()) j++;
          
          if (j < lines.length && /fn\s+\w+\(.*:\s*u256/.test(lines[j])) {
            const funcLine = lines[j];
            
            // Skip functions that have inherent validation
            let hasInherentValidation = false;
            for (const autoFunc of autoValidatedFunctions) {
              if (new RegExp(`fn\\s+\\w*${autoFunc}`).test(funcLine)) {
                hasInherentValidation = true;
                break;
              }
            }
            
            // Check for validation (expanded range and patterns)
            let hasValidation = false;
            for (let k = j; k < Math.min(j + 15, lines.length); k++) {
              // More comprehensive validation patterns
              if (/assert|require|is_zero|>=|<=|>|<|!=\s*0|balance.*>=/.test(lines[k])) {
                hasValidation = true;
                break;
              }
            }
            
            // Only flag if no validation AND no inherent validation
            if (!hasValidation && !hasInherentValidation) return true;
          }
        }
      }
      return false;
    }
  },
  {
    id: 'cairo-dangerous-delegate-call',
    name: 'Dangerous Library Call',
    severity: 'Critical',
    description: 'library_call should only be used with trusted contracts.',
    pattern: /library_call/,
    swcId: 'SWC-112',
    csrId: 'CSR-009',
    detector: (code: string): boolean => {
      return /library_call/.test(code);
    }
  },
  {
    id: 'cairo-missing-constructor',
    name: 'Missing Constructor Validation',
    severity: 'Medium',
    description: 'Constructor should validate initial parameters.',
    pattern: /#\[constructor\]/,
    csrId: 'CSR-011',
    detector: (code: string): boolean => {
      const lines = code.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (/#\[constructor\]/.test(lines[i])) {
          // Check next 10 lines for validation
          let hasValidation = false;
          for (let k = i; k < Math.min(i + 10, lines.length); k++) {
            if (/assert|is_zero|is_non_zero/.test(lines[k])) {
              hasValidation = true;
              break;
            }
          }
          if (!hasValidation) return true;
        }
      }
      return false;
    }
  },
  {
    id: 'cairo-array-out-of-bounds',
    name: 'Potential Array Out of Bounds',
    severity: 'High',
    description: 'Array access should be bounds-checked.',
    pattern: /\.at\(|\.get\(/,
    csrId: 'CSR-012',
    detector: (code: string): boolean => {
      const lines = code.split('\n');
      for (const line of lines) {
        if (/\.at\(/.test(line)) {
          // Check if index is validated
          if (!/assert.*<.*\.len\(|if.*<.*\.len\(/.test(line)) {
            return true;
          }
        }
      }
      return false;
    }
  },
  {
    id: 'cairo-unchecked-math',
    name: 'Unchecked Arithmetic',
    severity: 'High',
    description: 'Use checked arithmetic operations or explicitly handle overflow.',
    pattern: /[\+\-\*\/]/,
    csrId: 'CSR-013',
    detector: (code: string): boolean => {
      const lines = code.split('\n');
      for (const line of lines) {
        if (/let\s+\w+\s*=.*[\+\-\*]/.test(line) && /felt252|u256/.test(line)) {
          // Check if using checked operations
          if (!/checked_add|checked_sub|checked_mul|checked_div/.test(line)) {
            return true;
          }
        }
      }
      return false;
    }
  }
];
