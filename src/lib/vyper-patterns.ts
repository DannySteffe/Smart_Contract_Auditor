// Vyper-specific Vulnerability Patterns

export interface VyperVulnerabilityPattern {
  id: string;
  name: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  description: string;
  pattern: RegExp;
  swcId?: string;
  vsrId?: string; // Vyper Security Registry ID
  detector: (code: string) => boolean;
}

export const VYPER_VULNERABILITY_PATTERNS: VyperVulnerabilityPattern[] = [
  {
    id: 'vyper-reentrancy',
    name: 'Potential Reentrancy Vulnerability',
    severity: 'Critical',
    description: 'External call detected before state changes. Follow checks-effects-interactions pattern.',
    pattern: /send\(|raw_call\(/,
    swcId: 'SWC-107',
    vsrId: 'VSR-001',
    detector: (code: string): boolean => {
      // Look for external calls (send, raw_call) before state changes
      const lines = code.split('\n');
      let inFunction = false;
      let hasExternalCall = false;
      let hasStateChange = false;

      for (const line of lines) {
        if (/def\s+\w+/.test(line)) {
          inFunction = true;
          hasExternalCall = false;
          hasStateChange = false;
        }

        if (inFunction) {
          if (/send\(|raw_call\(/.test(line)) {
            hasExternalCall = true;
          }
          if (hasExternalCall && /self\.\w+\s*=/.test(line)) {
            hasStateChange = true;
            return true; // State change after external call
          }
        }
      }
      return false;
    }
  },
  {
    id: 'vyper-unchecked-send',
    name: 'Unchecked Send Return Value',
    severity: 'High',
    description: 'The return value of send() is not checked. Failed sends should be handled.',
    pattern: /\.send\(/,
    swcId: 'SWC-104',
    vsrId: 'VSR-002',
    detector: (code: string): boolean => {
      const lines = code.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/\.send\(/.test(line)) {
          // Check if return value is assigned or checked
          if (!/\w+\s*=.*\.send\(/.test(line) && !/assert\s+.*\.send\(/.test(line)) {
            return true;
          }
        }
      }
      return false;
    }
  },
  {
    id: 'vyper-integer-overflow',
    name: 'Potential Integer Overflow',
    severity: 'High',
    description: 'Arithmetic operations without overflow checks in older Vyper versions.',
    pattern: /\+|\-|\*|\/\//,
    vsrId: 'VSR-003',
    detector: (code: string): boolean => {
      // Check Vyper version - 0.3.0+ has built-in overflow protection
      const versionMatch = code.match(/#\s*@version\s+[\^]?([0-9]+)\.([0-9]+)/);
      if (versionMatch) {
        const major = parseInt(versionMatch[1]);
        const minor = parseInt(versionMatch[2]);
        // Vyper 0.3.0 and above has built-in overflow protection
        if (major > 0 || (major === 0 && minor >= 3)) {
          return false;
        }
      }
      
      // Look for unchecked arithmetic
      return /[\w\[\]\.]+\s*[\+\-\*]=\s*[\w\[\]\.]+/.test(code);
    }
  },
  {
    id: 'vyper-tx-origin',
    name: 'Use of tx.origin for Authorization',
    severity: 'High',
    description: 'tx.origin should not be used for authorization as it can be exploited in phishing attacks.',
    pattern: /tx\.origin/,
    vsrId: 'VSR-004',
    swcId: 'SWC-115',
    detector: (code: string): boolean => {
      return /tx\.origin/.test(code) && /assert|require|if/.test(code);
    }
  },
  {
    id: 'vyper-unprotected-function',
    name: 'Unprotected External Function',
    severity: 'High',
    description: 'External function lacks access control. Consider adding @onlyowner or permission checks.',
    vsrId: 'VSR-005',
    pattern: /@external\s*\n\s*def/,
    detector: (code: string): boolean => {
      const lines = code.split('\n');
      
      // Functions that should be accessible to everyone (not privileged)
      const publicUserFunctions = ['deposit', 'withdraw', 'transfer', 'approve', 'allowance', 'balance_of', 'total_supply', 'stake', 'unstake', 'claim'];
      
      for (let i = 0; i < lines.length; i++) {
        if (/@external/.test(lines[i])) {
          // Look ahead for function definition
          let j = i + 1;
          while (j < lines.length && !lines[j].trim()) j++;
          
          // Only check privileged functions
          if (j < lines.length && /def\s+(transfer_ownership|set_owner|emergency|pause|unpause|mint|burn|set_|update_)/.test(lines[j])) {
            const funcLine = lines[j];
            
            // Skip if it's a normal user function
            let isPublicUserFunc = false;
            for (const publicFunc of publicUserFunctions) {
              if (new RegExp(`def\\s+${publicFunc}`).test(funcLine)) {
                isPublicUserFunc = true;
                break;
              }
            }
            
            if (isPublicUserFunc) continue;
            
            // Check if there's access control (expanded patterns)
            let foundAccessControl = false;
            for (let k = j; k < Math.min(j + 15, lines.length); k++) {
              // Recognize various access control patterns including helper functions
              if (/assert\s+msg\.sender\s*==|assert\s+self\.owner\s*==|self\._only_owner\(|self\.assert_only_owner\(|@only_owner/.test(lines[k])) {
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
    id: 'vyper-missing-zero-check',
    name: 'Missing Zero Address Check',
    severity: 'Medium',
    vsrId: 'VSR-006',
    description: 'Address parameter should be checked against zero address.',
    pattern: /@external.*def.*\(.*:\s*address/,
    detector: (code: string): boolean => {
      const lines = code.split('\n');
      
      // Only check critical functions where zero address matters
      const criticalFunctions = ['transfer_ownership', 'set_owner', 'update_owner', 'transfer_to', 'send_to'];
      
      for (let i = 0; i < lines.length; i++) {
        if (/@external/.test(lines[i])) {
          let j = i + 1;
          while (j < lines.length && !lines[j].trim()) j++;
          
          if (j < lines.length && /def\s+\w+\([^)]*:\s*address/.test(lines[j])) {
            const funcLine = lines[j];
            
            // Only check critical functions
            let isCritical = false;
            for (const critFunc of criticalFunctions) {
              if (new RegExp(critFunc, 'i').test(funcLine)) {
                isCritical = true;
                break;
              }
            }
            
            if (!isCritical) continue;
            
            // Check if there's a zero address check (expanded range and patterns)
            let hasZeroCheck = false;
            for (let k = j; k < Math.min(j + 10, lines.length); k++) {
              if (/assert.*!=\s*ZERO_ADDRESS|assert.*!=\s*empty\(address\)|assert.*!=\s*0x0|assert\s+\w+/.test(lines[k])) {
                hasZeroCheck = true;
                break;
              }
            }
            if (!hasZeroCheck) return true;
          }
        }
      }
      return false;
    }
  },
  {
    id: 'vyper-timestamp-dependency',
    name: 'Timestamp Dependence',
    severity: 'Medium',
    description: 'Using block.timestamp for critical logic can be manipulated by miners.',
    pattern: /block\.timestamp/,
    swcId: 'SWC-116',    vsrId: 'VSR-007',    detector: (code: string): boolean => {
      return /block\.timestamp/.test(code) && /(if|assert|require).*block\.timestamp/.test(code);
    }
  },
  {
    id: 'vyper-unsafe-type-inference',
    name: 'Unsafe Type Inference',
    severity: 'Medium',
    description: 'Missing explicit type annotations can lead to unexpected behavior.',
    pattern: /def\s+\w+\([^)]*\):/,
    vsrId: 'VSR-013',
    detector: (code: string): boolean => {
      const lines = code.split('\n');
      for (const line of lines) {
        if (/def\s+\w+\([^)]+\):/.test(line)) {
          // Check if parameters have type annotations
          const paramMatch = line.match(/def\s+\w+\(([^)]+)\):/);
          if (paramMatch) {
            const params = paramMatch[1];
            // Check if any param is missing type annotation
            const paramList = params.split(',');
            for (const param of paramList) {
              if (param.trim() && !/:/.test(param)) {
                return true;
              }
            }
          }
        }
      }
      return false;
    }
  },
  {
    id: 'vyper-unchecked-raw-call',
    name: 'Unchecked raw_call Return Value',
    severity: 'High',
    description: 'raw_call return value should always be checked for success.',
    pattern: /raw_call\(/,
    vsrId: 'VSR-002',
    detector: (code: string): boolean => {
      const lines = code.split('\n');
      for (const line of lines) {
        if (/raw_call\(/.test(line)) {
          // Check if success value is checked
          if (!/success\s*:=.*raw_call|_success.*raw_call/.test(line)) {
            return true;
          }
        }
      }
      return false;
    }
  },
  {
    id: 'vyper-selfdestruct',
    name: 'Use of selfdestruct',
    severity: 'Critical',
    description: 'selfdestruct can permanently destroy the contract. Use with extreme caution.',
    vsrId: 'VSR-010',
    pattern: /selfdestruct\(/,
    detector: (code: string): boolean => {
      return /selfdestruct\(/.test(code);
    }
  },
  {
    id: 'vyper-delegatecall',
    name: 'Dangerous delegatecall Usage',
    severity: 'Critical',
    description: 'raw_call with is_delegate_call=True can be exploited if target is not trusted.',
    pattern: /raw_call\(.*is_delegate_call\s*=\s*True/,
    vsrId: 'VSR-009',
    swcId: 'SWC-112',
    detector: (code: string): boolean => {
      return /raw_call\(.*is_delegate_call\s*=\s*True/.test(code);
    }
  },
  {
    id: 'vyper-missing-event',
    name: 'Missing Event Emission',
    severity: 'Low',
    vsrId: 'VSR-014',
    description: 'Critical state changes should emit events for off-chain tracking.',
    pattern: /@external.*def.*(transfer|mint|burn|withdraw)/,
    detector: (code: string): boolean => {
      const lines = code.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (/@external/.test(lines[i])) {
          let j = i + 1;
          while (j < lines.length && !lines[j].trim()) j++;
          
          if (j < lines.length && /def\s+(transfer|mint|burn|withdraw)/.test(lines[j])) {
            // Check if event is logged
            let hasEvent = false;
            for (let k = j; k < Math.min(j + 20, lines.length); k++) {
              if (/log\s+\w+/.test(lines[k])) {
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
    id: 'vyper-outdated-version',
    name: 'Outdated Compiler Version',
    severity: 'Medium',
    description: 'Using an outdated Vyper version may include known vulnerabilities.',
    vsrId: 'VSR-015',
    pattern: /#\s*@version/,
    swcId: 'SWC-102',
    detector: (code: string): boolean => {
      const versionMatch = code.match(/#\s*@version\s+[\^]?([0-9]+)\.([0-9]+)\.([0-9]+)/);
      if (versionMatch) {
        const major = parseInt(versionMatch[1]);
        const minor = parseInt(versionMatch[2]);
        const patch = parseInt(versionMatch[3]);
        
        // Recommend Vyper 0.3.7 or higher (as of 2024)
        if (major < 0 || (major === 0 && minor < 3) || (major === 0 && minor === 3 && patch < 7)) {
          return true;
        }
      }
      return false;
    }
  },
  {
    id: 'vyper-floating-pragma',
    name: 'Floating Pragma',
    severity: 'Low',
    description: 'Vyper version should be locked to a specific version.',
    pattern: /#\s*@version\s+\^/,
    vsrId: 'VSR-015',
    detector: (code: string): boolean => {
      return /#\s*@version\s+\^/.test(code);
    }
  },
  {
    id: 'vyper-division-before-multiplication',
    name: 'Division Before Multiplication',
    severity: 'Medium',
    description: 'Division before multiplication can cause precision loss.',
    pattern: /\/\/.*\*/,
    vsrId: 'VSR-003',
    detector: (code: string): boolean => {
      return /\S+\s*\/\/\s*\S+\s*\*\s*\S+/.test(code);
    }
  }
];
