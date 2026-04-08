// Multi-Language Static Analysis Service

import * as parser from '@solidity-parser/parser';
import { Vulnerability } from '@/types';
import { VULNERABILITY_PATTERNS } from './vulnerability-patterns';
import { getSWCById } from './swc-registry';
import { v4 as uuidv4 } from 'uuid';
import { detectLanguage, SmartContractLanguage } from './language-detector';
import { analyzeVyperContract } from './vyper-analyzer';
import { analyzeCairoContract } from './cairo-analyzer';

export interface StaticAnalysisResult {
  vulnerabilities: Vulnerability[];
  contractInfo: {
    name: string;
    functions: string[];
    stateVariables: string[];
    modifiers: string[];
  };
  language?: SmartContractLanguage;
}

export async function performStaticAnalysis(contractCode: string, fileName?: string): Promise<StaticAnalysisResult> {
  // Detect the language of the contract
  const langDetection = detectLanguage(contractCode, fileName);
  
  // Route to appropriate analyzer based on language
  if (langDetection.language === 'vyper') {
    const vyperResult = await analyzeVyperContract(contractCode);
    return {
      vulnerabilities: vyperResult.vulnerabilities,
      contractInfo: {
        name: vyperResult.contractInfo.name,
        functions: vyperResult.contractInfo.functions,
        stateVariables: vyperResult.contractInfo.storageVariables,
        modifiers: [] // Vyper doesn't have modifiers
      },
      language: 'vyper'
    };
  }
  
  if (langDetection.language === 'cairo') {
    const cairoResult = await analyzeCairoContract(contractCode);
    return {
      vulnerabilities: cairoResult.vulnerabilities,
      contractInfo: {
        name: cairoResult.contractInfo.name,
        functions: cairoResult.contractInfo.functions,
        stateVariables: cairoResult.contractInfo.storageVariables,
        modifiers: [] // Cairo doesn't have modifiers
      },
      language: 'cairo'
    };
  }
  
  // Default to Solidity analysis
  return performSolidityAnalysis(contractCode);
}

// Helper function to validate if code looks like Solidity
function isSolidityLike(code: string): boolean {
  // Check for common Solidity patterns
  const solidityIndicators = [
    /pragma\s+solidity/i,
    /\bcontract\s+\w+\s*\{/i,
    /\bfunction\s+\w+\s*\(/i,
    /\bmapping\s*\(/i,
    /\bmsg\./,
    /\bpayable\b/i
  ];

  const indicators = solidityIndicators.filter(pattern => pattern.test(code)).length;
  
  // Check for Cairo/Vyper patterns that would disqualify it as Solidity
  const nonSolidityIndicators = [
    /#\[starknet::contract\]/i,  // Cairo 1.0
    /^mod\s+\w+\s*\{/m,           // Cairo module
    /%lang\s+starknet/i,           // Cairo 0.x
    /def\s+\w+\s*\(/m,             // Vyper functions
    /@external\b|@internal\b|@view\b|@pure\b|@payable\b/i  // Modern decorators (Vyper/Cairo)
  ];

  const nonSolidityCount = nonSolidityIndicators.filter(pattern => pattern.test(code)).length;

  // If it has non-Solidity indicators and few Solidity indicators, reject it
  if (nonSolidityCount > 0 && indicators < 2) {
    return false;
  }

  // Accept if it has at least some Solidity indicators
  return indicators > 0;
}

async function performSolidityAnalysis(contractCode: string): Promise<StaticAnalysisResult> {
  const vulnerabilities: Vulnerability[] = [];
  const contractInfo = {
    name: 'Unknown',
    functions: [] as string[],
    stateVariables: [] as string[],
    modifiers: [] as string[]
  };

  const lines = contractCode.split('\n');
  let astParsingSuccess = false;

  try {
    // Validate that code looks like Solidity before parsing
    if (!isSolidityLike(contractCode)) {
      console.warn('Code does not appear to be Solidity, skipping AST parsing');
      astParsingSuccess = false;
    } else {
      // Parse the Solidity code
      const ast = parser.parse(contractCode, { tolerant: true, loc: true });

      // Extract contract information
      parser.visit(ast, {
        ContractDefinition: (node: any) => {
          contractInfo.name = node.name;
        },
        FunctionDefinition: (node: any) => {
          if (node.name) {
            contractInfo.functions.push(node.name);
          }
        },
        StateVariableDeclaration: (node: any) => {
          // Extract state variable names
          if (node.variables) {
            node.variables.forEach((v: any) => {
              if (v.name) {
                contractInfo.stateVariables.push(v.name);
              }
            });
          }
        },
        ModifierDefinition: (node: any) => {
          if (node.name) {
            contractInfo.modifiers.push(node.name);
          }
        }
      });

      astParsingSuccess = true;
    }
  } catch (error) {
    console.error('AST parsing error (continuing with pattern-based analysis):', error instanceof Error ? error.message : error);
    astParsingSuccess = false;
  }

  // Run pattern-based vulnerability detection (always runs, regardless of AST parsing)
  for (const pattern of VULNERABILITY_PATTERNS) {
    if (pattern.check(contractCode)) {
      const matches = findPatternMatches(contractCode, pattern);
      
      for (const match of matches) {
        const swc = getSWCById(pattern.swcId);
        
        vulnerabilities.push({
          id: uuidv4(),
          name: pattern.name,
          type: pattern.swcId,
          severity: pattern.severity,
          swcId: pattern.swcId,
          cweIds: swc?.cweIds || [],
          scsvIds: pattern.scsvIds || [],
          ethTrustImpact: getSeverityImpact(pattern.severity),
          lineNumber: match.lineNumber,
          lineRange: { start: match.lineNumber, end: match.lineNumber },
          codeSnippet: getCodeContext(lines, match.lineNumber, 2),
          description: swc?.description || pattern.description,
          exploitationScenario: astParsingSuccess ? 'See detailed analysis' : 'Requires detailed analysis',
          recommendation: swc?.remediation || 'Review and fix this issue',
          references: swc ? [`https://swcregistry.io/docs/${pattern.swcId}`] : [],
          detectionMethod: 'static',
          confidence: astParsingSuccess ? 'High' : 'Medium'
        });
      }
    }
  }

  return {
    vulnerabilities: removeDuplicates(vulnerabilities),
    contractInfo,
    language: 'solidity'
  };
}

function findPatternMatches(code: string, pattern: any): Array<{ lineNumber: number; match: string }> {
  const lines = code.split('\n');
  const matches: Array<{ lineNumber: number; match: string }> = [];

  lines.forEach((line, index) => {
    if (typeof pattern.pattern === 'string') {
      if (line.includes(pattern.pattern)) {
        matches.push({ lineNumber: index + 1, match: line.trim() });
      }
    } else if (pattern.pattern instanceof RegExp) {
      if (pattern.pattern.test(line)) {
        matches.push({ lineNumber: index + 1, match: line.trim() });
      }
    }
  });

  return matches.length > 0 ? matches : [{ lineNumber: 1, match: '' }];
}

function getCodeContext(lines: string[], lineNumber: number, contextLines: number = 2): string {
  const startLine = Math.max(0, lineNumber - contextLines - 1);
  const endLine = Math.min(lines.length, lineNumber + contextLines);
  return lines.slice(startLine, endLine).join('\n');
}

function getSeverityImpact(severity: string): number {
  const impacts: Record<string, number> = {
    'Critical': 1,
    'High': 2,
    'Medium': 3,
    'Low': 4,
    'Info': 5
  };
  return impacts[severity] || 3;
}

function removeDuplicates(vulnerabilities: Vulnerability[]): Vulnerability[] {
  const seen = new Set<string>();
  return vulnerabilities.filter(v => {
    const key = `${v.swcId}-${v.lineNumber}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

export function analyzeAccessControl(code: string): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];
  const lines = code.split('\n');

  // Check for functions without explicit visibility
  lines.forEach((line, index) => {
    if (/function\s+\w+/.test(line) && !/public|private|internal|external/.test(line)) {
      vulnerabilities.push({
        id: uuidv4(),
        name: 'Missing Function Visibility',
        type: 'SWC-100',
        severity: 'High',
        swcId: 'SWC-100',
        cweIds: ['CWE-710'],
        scsvIds: ['V2.1'],
        ethTrustImpact: 2,
        lineNumber: index + 1,
        codeSnippet: line.trim(),
        description: 'Function does not have explicit visibility modifier',
        exploitationScenario: 'Function defaults to public, potentially exposing internal logic',
        recommendation: 'Add explicit visibility modifier (public, external, internal, or private)',
        references: ['https://swcregistry.io/docs/SWC-100'],
        detectionMethod: 'static',
        confidence: 'High'
      });
    }
  });

  return vulnerabilities;
}

export function analyzeReentrancy(code: string): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];
  const lines = code.split('\n');
  
  lines.forEach((line, index) => {
    if (/\.call\{value:/.test(line) || /\.transfer\(/.test(line) || /\.send\(/.test(line)) {
      // Check if state changes after external call
      const remainingCode = lines.slice(index).join('\n');
      if (/=\s*\w+|\.push\(|balances\[/.test(remainingCode.substring(0, 500))) {
        vulnerabilities.push({
          id: uuidv4(),
          name: 'Potential Reentrancy Vulnerability',
          type: 'SWC-107',
          severity: 'Critical',
          swcId: 'SWC-107',
          cweIds: ['CWE-841'],
          scsvIds: ['V6.1'],
          ethTrustImpact: 1,
          lineNumber: index + 1,
          codeSnippet: line.trim(),
          description: 'External call detected with state changes afterward',
          exploitationScenario: 'Attacker can recursively call this function before state is updated',
          recommendation: 'Use Checks-Effects-Interactions pattern. Update state before external calls.',
          references: ['https://swcregistry.io/docs/SWC-107'],
          detectionMethod: 'static',
          confidence: 'High'
        });
      }
    }
  });

  return vulnerabilities;
}
