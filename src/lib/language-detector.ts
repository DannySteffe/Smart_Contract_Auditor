// Language Detection Utility for Smart Contracts

export type SmartContractLanguage = 'solidity' | 'vyper' | 'cairo' | 'unknown';

export interface LanguageDetectionResult {
  language: SmartContractLanguage;
  confidence: number;
  version?: string;
}

export function detectLanguage(code: string, fileName?: string): LanguageDetectionResult {
  // Detect by content first
  const solidityResult = detectSolidity(code);
  const vyperResult = detectVyper(code);
  const cairoResult = detectCairo(code);

  const results = [solidityResult, vyperResult, cairoResult];

  // Use file extension as a soft hint (not a hard override)
  if (fileName) {
    const lowerFileName = fileName.toLowerCase();
    if (lowerFileName.endsWith('.sol')) {
      solidityResult.confidence += 12;
    } else if (lowerFileName.endsWith('.vy')) {
      vyperResult.confidence += 12;
    } else if (lowerFileName.endsWith('.cairo')) {
      cairoResult.confidence += 12;
    }
  }

  // Return the one with highest confidence
  results.sort((a, b) => b.confidence - a.confidence);
  return results[0];
}

function detectSolidity(code: string): LanguageDetectionResult {
  let confidence = 0;
  let version: string | undefined;

  // Check for pragma solidity
  if (/pragma\s+solidity/i.test(code)) {
    confidence += 40;
    const versionMatch = code.match(/pragma\s+solidity\s+[\^]?([0-9]+\.[0-9]+\.[0-9]+)/);
    if (versionMatch) {
      version = versionMatch[1];
    }
  }

  // Check for Solidity-specific keywords
  if (/\bcontract\s+\w+/i.test(code)) confidence += 20;
  if (/\bmapping\s*\(/i.test(code)) confidence += 10;
  if (/\bmodifier\s+\w+/i.test(code)) confidence += 10;
  if (/\bmsg\.sender\b/i.test(code)) confidence += 5;
  if (/\bpayable\b/i.test(code)) confidence += 5;
  if (/\bfunction\s+\w+.*\breturns\b/i.test(code)) confidence += 10;

  return {
    language: confidence > 30 ? 'solidity' : 'unknown',
    confidence,
    version
  };
}

function detectVyper(code: string): LanguageDetectionResult {
  let confidence = 0;
  let version: string | undefined;

  // Check for Vyper version pragma
  if (/#\s*@version\s+[\^]?([0-9]+\.[0-9]+\.[0-9]+)/i.test(code)) {
    confidence += 40;
    const versionMatch = code.match(/#\s*@version\s+[\^]?([0-9]+\.[0-9]+\.[0-9]+)/);
    if (versionMatch) {
      version = versionMatch[1];
    }
  }

  // Check for Vyper-specific decorators
  if (/@external\b/i.test(code)) confidence += 15;
  if (/@internal\b/i.test(code)) confidence += 10;
  if (/@view\b/i.test(code)) confidence += 10;
  if (/@pure\b/i.test(code)) confidence += 10;
  if (/@payable\b/i.test(code)) confidence += 10;

  // Check for Vyper-specific syntax
  if (/def\s+\w+\s*\(/i.test(code)) confidence += 10;
  if (/:\s*(public|private)\(/i.test(code)) confidence += 10;
  if (/event\s+\w+:/i.test(code)) confidence += 5;
  if (/implements:\s*\w+/i.test(code)) confidence += 10;
  
  // Python-like syntax indicators
  if (/^[ \t]+(def|if|for|while)\s/m.test(code)) confidence += 5;

  return {
    language: confidence > 30 ? 'vyper' : 'unknown',
    confidence,
    version
  };
}

function detectCairo(code: string): LanguageDetectionResult {
  let confidence = 0;
  let version: string | undefined;

  // Check for Cairo-specific imports
  if (/%lang\s+starknet/i.test(code)) {
    confidence += 40;
    version = '0.x';
  }

  // Check for Cairo 1.0+ syntax
  if (/#\[starknet::contract\]/i.test(code)) {
    confidence += 40;
    version = '1.x';
  }

  // Check for Cairo-specific attributes (both @ and #[ styles)
  if (/@external\b|#\[external/i.test(code)) confidence += 10;
  if (/@view\b|#\[view/i.test(code)) confidence += 10;
  if (/@storage_var\b|#\[storage/i.test(code)) confidence += 15;
  if (/@constructor\b|#\[constructor/i.test(code)) confidence += 10;
  if (/@event\b|#\[event/i.test(code)) confidence += 5;

  // Cairo-specific types and syntax
  if (/\bfelt\b/i.test(code)) confidence += 15;
  if (/\bu256\b/i.test(code)) confidence += 10;
  if (/\blet\s+\w+\s*=/i.test(code)) confidence += 5;
  if (/use\s+starknet::|use\s+\w+::/i.test(code)) confidence += 10;
  if (/\bimpl\s+\w+/i.test(code)) confidence += 10;
  if (/\bfn\s+\w+/i.test(code)) confidence += 10;
  if (/\bmod\s+\w+\s*\{/i.test(code)) confidence += 15;  // Cairo module
  if (/LegacyMap|ContractAddress/i.test(code)) confidence += 15;  // Cairo-specific types

  return {
    language: confidence > 25 ? 'cairo' : 'unknown',  // Lowered threshold from 30 to 25
    confidence,
    version
  };
}

export function getLanguageFileExtension(language: SmartContractLanguage): string {
  switch (language) {
    case 'solidity':
      return '.sol';
    case 'vyper':
      return '.vy';
    case 'cairo':
      return '.cairo';
    default:
      return '.txt';
  }
}

export function getLanguageName(language: SmartContractLanguage): string {
  switch (language) {
    case 'solidity':
      return 'Solidity';
    case 'vyper':
      return 'Vyper';
    case 'cairo':
      return 'Cairo';
    default:
      return 'Unknown';
  }
}
