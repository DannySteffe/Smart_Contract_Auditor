// Plain Text Audit Report Generator
// Generates professional, industry-standard audit reports in plain text format

import { AnalysisResult } from '@/types';
import { getEthTrustLevelDefinition } from './ethtrust';

// ============================================================================
// HELPER FUNCTIONS (Defined First)
// ============================================================================

function calculateContractMetrics(code: string, language: string) {
  const loc = code.split('\n').length;
  
  // Basic pattern matching for different languages
  let functions = 0;
  let stateVariables = 0;
  let externalCalls = 0;
  let compilerVersion = null;

  if (language.toLowerCase() === 'solidity') {
    functions = (code.match(/function\s+\w+\s*\(/g) || []).length;
    stateVariables = (code.match(/^\s*(?:public|private|internal|protected)?\s+\w+\s+\w+\s*[=;]/gm) || []).length;
    externalCalls = (code.match(/\.\s*call|\.transfer|\.send/g) || []).length;
    const versionMatch = code.match(/pragma\s+solidity\s+(\^?[\d\.]+)?/);
    compilerVersion = versionMatch ? versionMatch[1] : null;
  } else if (language.toLowerCase() === 'vyper') {
    functions = (code.match(/@external|@internal|def\s+\w+\s*\(/g) || []).length;
    stateVariables = (code.match(/^\s*\w+\s*:\s*\w+/gm) || []).length;
    externalCalls = (code.match(/send|call/g) || []).length;
    const versionMatch = code.match(/#\s*@version\s+(.+)/);
    compilerVersion = versionMatch ? versionMatch[1] : null;
  } else if (language.toLowerCase() === 'cairo') {
    functions = (code.match(/fn\s+\w+/g) || []).length;
    stateVariables = (code.match(/#\[storage_var\]/g) || []).length;
    externalCalls = (code.match(/call_contract|send_message/g) || []).length;
  }

  return {
    loc,
    functions,
    stateVariables,
    externalCalls,
    compilerVersion
  };
}

function groupVulnerabilitiesBySeverity(vulns: any[]) {
  return vulns.reduce((acc, vuln) => {
    if (!acc[vuln.severity]) {
      acc[vuln.severity] = [];
    }
    acc[vuln.severity].push(vuln);
    return acc;
  }, {} as Record<string, any[]>);
}

function groupBySwcId(vulns: any[]) {
  return vulns.reduce((acc, vuln) => {
    if (!acc[vuln.swcId]) {
      acc[vuln.swcId] = [];
    }
    acc[vuln.swcId].push(vuln);
    return acc;
  }, {} as Record<string, any[]>);
}

function groupByConfidence(vulns: any[]) {
  return vulns.reduce((acc, vuln) => {
    const conf = vuln.confidence || 'Low';
    acc[conf] = (acc[conf] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
}

function calculateAverageConfidence(vulns: any[]): string {
  if (vulns.length === 0) return 'N/A';
  
  const confidenceScores: Record<string, number> = { High: 3, Medium: 2, Low: 1 };
  const totalScore = vulns.reduce((sum, v) => sum + (confidenceScores[v.confidence] || 1), 0);
  const avgScore = totalScore / vulns.length;
  
  if (avgScore >= 2.5) return 'High';
  if (avgScore >= 1.5) return 'Medium';
  return 'Low';
}

function calculateRiskBreakdown(result: any) {
  const total = result.statistics.total || 1;
  return {
    Critical: {
      count: result.statistics.critical,
      percentage: (result.statistics.critical / total) * 100
    },
    High: {
      count: result.statistics.high,
      percentage: (result.statistics.high / total) * 100
    },
    Medium: {
      count: result.statistics.medium,
      percentage: (result.statistics.medium / total) * 100
    },
    Low: {
      count: result.statistics.low,
      percentage: (result.statistics.low / total) * 100
    },
    Info: {
      count: result.statistics.info,
      percentage: (result.statistics.info / total) * 100
    }
  };
}

function formatRiskChart(breakdown: Record<string, any>): string {
  const chart: string[] = [];
  const maxBarLength = 40;

  Object.entries(breakdown).forEach(([severity, data]) => {
    const barLength = Math.round((data.percentage / 100) * maxBarLength);
    const bar = '█'.repeat(barLength) + '░'.repeat(maxBarLength - barLength);
    const label = severity.padEnd(8);
    const percentage = data.percentage.toFixed(1).padStart(5);
    chart.push(`  ${label} │ ${bar} │ ${percentage}%`);
  });

  return chart.join('\n');
}

function wrapText(text: string, maxWidth: number): string[] {
  const lines: string[] = [];
  const words = text.split(' ');
  let currentLine = '';

  words.forEach(word => {
    if ((currentLine + word).length > maxWidth) {
      if (currentLine.trim()) {
        lines.push(currentLine.trim());
      }
      currentLine = word + ' ';
    } else {
      currentLine += word + ' ';
    }
  });

  if (currentLine.trim()) {
    lines.push(currentLine.trim());
  }

  return lines;
}

function centerText(text: string, width: number): string {
  const padding = Math.max(0, Math.floor((width - text.length) / 2));
  return ' '.repeat(padding) + text + ' '.repeat(width - padding - text.length);
}

function capitalizeFirst(str: string): string {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

function getScoreRating(score: number): string {
  if (score >= 90) return 'Excellent - Contract meets highest security standards';
  if (score >= 75) return 'Good - Contract is generally secure with minor concerns';
  if (score >= 60) return 'Fair - Contract has moderate security concerns';
  if (score >= 40) return 'Poor - Contract has significant security issues';
  return 'Critical - Contract requires immediate remediation';
}

function getImpactDescription(severity: string): string {
  const impacts: Record<string, string> = {
    Critical: 'complete loss of funds or contract control',
    High: 'significant loss of funds or contract compromise',
    Medium: 'moderate financial loss or unexpected behavior',
    Low: 'minor financial loss or optimization opportunity',
    Info: 'best practice recommendation or informational finding'
  };
  return impacts[severity] || 'undefined impact';
}

// ============================================================================
// MAIN REPORT GENERATOR
// ============================================================================

export function generateTextAuditReport(result: AnalysisResult): string {
  const lines: string[] = [];
  const separator = '─'.repeat(80);
  const doubleSeparator = '═'.repeat(80);

  // Helper functions
  const addLine = (text: string = '') => lines.push(text);
  const addSection = (title: string) => {
    addLine();
    addLine(doubleSeparator);
    addLine(`  ${title}`);
    addLine(doubleSeparator);
  };
  const addSubsection = (title: string) => {
    addLine();
    addLine(separator);
    addLine(`  ${title}`);
    addLine(separator);
  };

  // Calculate contract metrics
  const contractMetrics = calculateContractMetrics(result.contractCode, result.language || 'unknown');
  const ethTrustDef = getEthTrustLevelDefinition(result.ethTrustLevel);

  // ============================================================================
  // TITLE & HEADER
  // ============================================================================
  addLine();
  addLine('╔' + '═'.repeat(78) + '╗');
  addLine('║' + ' '.repeat(78) + '║');
  addLine('║' + centerText('AGENTIC FRAMEWORK FOR SMART CONTRACT SECURITY AUDIT REPORT', 78) + '║');
  addLine('║' + ' '.repeat(78) + '║');
  addLine('╚' + '═'.repeat(78) + '╝');
  addLine();

  // ============================================================================
  // EXECUTIVE SUMMARY
  // ============================================================================
  addSection('EXECUTIVE SUMMARY');
  addLine(`Security Score:              ${result.securityScore}/100`);
  addLine(`Risk Level:                  ${result.riskLevel.toUpperCase()}`);
  addLine(`Analysis Date:               ${new Date(result.timestamp).toLocaleDateString()}`);
  addLine(`Analysis Time:               ${new Date(result.timestamp).toLocaleTimeString()}`);
  addLine(`Audit Duration:              ${(result.analysisTime / 1000).toFixed(2)}s`);
  addLine();
  addLine(`Contract Language:           ${result.language?.toUpperCase() || 'UNKNOWN'}`);
  addLine(`Audit ID:                    ${result.analysisId}`);
  addLine();
  addLine('Issue Breakdown:');
  addLine(`  • Critical Issues:         ${result.statistics.critical}`);
  addLine(`  • High Severity Issues:    ${result.statistics.high}`);
  addLine(`  • Medium Severity Issues:  ${result.statistics.medium}`);
  addLine(`  • Low Severity Issues:     ${result.statistics.low}`);
  addLine(`  • Informational Issues:    ${result.statistics.info}`);
  addLine(`  • Total Issues:            ${result.statistics.total}`);

  // ============================================================================
  // CONTRACT DETAILS
  // ============================================================================
  addSection('CONTRACT DETAILS');
  addLine(`File Name:                   ${result.fileName}`);
  addLine(`File Size:                   ${(result.contractCode.length / 1024).toFixed(2)} KB`);
  addLine(`Language:                    ${result.language?.toUpperCase() || 'UNKNOWN'}`);
  addLine();
  addLine('Code Metrics:');
  addLine(`  • Lines of Code (LOC):     ${contractMetrics.loc}`);
  addLine(`  • Number of Functions:     ${contractMetrics.functions}`);
  addLine(`  • External Calls:          ${contractMetrics.externalCalls}`);
  addLine(`  • State Variables:         ${contractMetrics.stateVariables}`);
  addLine(`  • Compiler Version:        ${contractMetrics.compilerVersion || 'N/A'}`);

  // ============================================================================
  // SECURITY ASSESSMENT
  // ============================================================================
  addSection('SECURITY ASSESSMENT');
  
  const scoreRating = getScoreRating(result.securityScore);
  addLine(`Overall Risk Assessment:     ${scoreRating}`);
  addLine();
  addLine(`EthTrust Security Level:     Level ${ethTrustDef.level}`);
  addLine(`  Name:                      ${ethTrustDef.name}`);
  addLine(`  Risk Category:             ${ethTrustDef.risk}`);
  addLine(`  Description:               ${ethTrustDef.description}`);
  addLine();
  addLine('SCSVS v2 Compliance:');
  addLine(`  • Compliance Percentage:   ${result.scsvCompliance.percentage}%`);
  addLine(`  • Checks Passed:           ${result.scsvCompliance.passed}`);
  addLine(`  • Checks Failed:           ${result.scsvCompliance.failed}`);

  // ============================================================================
  // DETAILED VULNERABILITY REPORT
  // ============================================================================
  if (result.vulnerabilities.length > 0) {
    addSection('DETAILED VULNERABILITY REPORT');
    addLine(`Total Vulnerabilities Found: ${result.vulnerabilities.length}`);
    addLine();

    // Group vulnerabilities by severity
    const vulnBySeverity = groupVulnerabilitiesBySeverity(result.vulnerabilities);
    const severityOrder = ['Critical', 'High', 'Medium', 'Low', 'Info'];

    severityOrder.forEach((severity: string) => {
      const vulns = vulnBySeverity[severity] || [];
      if (vulns.length > 0) {
        addSubsection(`${severity.toUpperCase()} SEVERITY VULNERABILITIES (${vulns.length})`);
        
        vulns.forEach((vuln: any, index: number) => {
          addLine();
          addLine(`[${index + 1}] ${vuln.name}`);
          addLine(`    Severity:               ${vuln.severity}`);
          addLine(`    Confidence:            ${vuln.confidence}`);
          addLine(`    Line Number:           ${vuln.lineNumber}${vuln.lineRange ? ` (Range: ${vuln.lineRange.start}-${vuln.lineRange.end})` : ''}`);
          addLine(`    Detection Method:      ${capitalizeFirst(vuln.detectionMethod)}`);
          addLine(`    CWE ID:                ${vuln.swcId}`);
          
          if (vuln.cweIds && vuln.cweIds.length > 0) {
            addLine(`    CWE References:        ${vuln.cweIds.join(', ')}`);
          }
          
          addLine();
          addLine('    DESCRIPTION:');
          wrapText(vuln.description, 75).forEach((line: string) => addLine(`    ${line}`));
          
          addLine();
          addLine('    EXPLOITATION SCENARIO:');
          wrapText(vuln.exploitationScenario || 'N/A', 75).forEach((line: string) => addLine(`    ${line}`));
          
          addLine();
          addLine('    IMPACT:');
          addLine(`    This vulnerability could lead to ${getImpactDescription(vuln.severity)}.`);
          
          addLine();
          addLine('    RECOMMENDATION:');
          wrapText(vuln.recommendation, 75).forEach((line: string) => addLine(`    ${line}`));
          
          if (vuln.references && vuln.references.length > 0) {
            addLine();
            addLine('    REFERENCES:');
            vuln.references.forEach((ref: string) => addLine(`    • ${ref}`));
          }
          
          addLine();
          addLine(`    ${'─'.repeat(76)}`);
        });
      }
    });
  } else {
    addSection('DETAILED VULNERABILITY REPORT');
    addLine();
    addLine('✓ NO VULNERABILITIES DETECTED');
    addLine();
    addLine('This smart contract passed all security checks with no issues found.');
  }

  // ============================================================================
  // AI INSIGHTS & CONFIDENCE ANALYSIS
  // ============================================================================
  addSection('AI INSIGHTS & CONFIDENCE ANALYSIS');
  
  const aiVulns = result.vulnerabilities.filter(v => v.detectionMethod === 'ai' || v.detectionMethod === 'hybrid');
  const confidence = calculateAverageConfidence(result.vulnerabilities);
  
  addLine(`AI-Detected Issues:          ${aiVulns.length}`);
  addLine(`Average Confidence Level:    ${confidence}`);
  addLine();
  addLine('Confidence Breakdown:');
  
  const confidenceByLevel = groupByConfidence(result.vulnerabilities);
  Object.entries(confidenceByLevel).forEach(([level, count]) => {
    addLine(`  • ${level}:                   ${count as number} findings`);
  });
  
  addLine();
  addLine('AI Analysis Notes:');
  addLine('• This audit includes AI-powered analysis using advanced machine learning');
  addLine('  models trained on known vulnerability patterns and code semantics.');
  addLine('• AI confidence levels indicate the model\'s certainty about each finding.');
  addLine('• All AI findings have been validated and cross-referenced against');
  addLine('  established security standards (SWC Registry, CWE, etc.).');

  // ============================================================================
  // COMPLIANCE METRICS
  // ============================================================================
  addSection('COMPLIANCE METRICS');
  
  addSubsection('Smart Contract Weakness Classification (SWC) Registry');
  const swcVulns = groupBySwcId(result.vulnerabilities);
  if (Object.keys(swcVulns).length > 0) {
    Object.entries(swcVulns).forEach(([swcId, vulns]) => {
      addLine(`  • ${swcId}: ${(vulns as any[]).length} finding(s)`);
    });
  } else {
    addLine('  No SWC-mapped vulnerabilities detected.');
  }

  addSubsection('Secure Coding Verification Standard (SCSVS) v2');
  addLine(`Overall Compliance: ${result.scsvCompliance.percentage}%`);
  addLine();
  if (result.scsvCompliance.checklist && result.scsvCompliance.checklist.length > 0) {
    addLine('Failed Controls:');
    const failedControls = result.scsvCompliance.checklist.filter(c => !c.passed);
    if (failedControls.length > 0) {
      failedControls.slice(0, 10).forEach(control => {
        addLine(`  • [${control.controlId}] ${control.title}`);
        if (control.findings && control.findings.length > 0) {
          control.findings.slice(0, 2).forEach(finding => {
            addLine(`      - ${finding}`);
          });
        }
      });
      if (failedControls.length > 10) {
        addLine(`  ... and ${failedControls.length - 10} more controls`);
      }
    } else {
      addLine('  All SCSVS v2 controls passed.');
    }
  }

  addSubsection('EthTrust Framework');
  addLine(`Security Level:              Level ${ethTrustDef.level}`);
  addLine(`Classification:              ${ethTrustDef.name}`);
  addLine(`Risk Rating:                 ${ethTrustDef.risk}`);
  addLine();
  addLine('Framework Details:');
  addLine(`  • Description:             ${ethTrustDef.description}`);

  // ============================================================================
  // RISK BREAKDOWN ANALYSIS
  // ============================================================================
  addSection('RISK BREAKDOWN ANALYSIS');
  
  const riskBreakdown = calculateRiskBreakdown(result);
  addLine('Risk Distribution by Severity:');
  addLine();
  addLine(formatRiskChart(riskBreakdown));
  addLine();
  addLine('Risk Summary Table:');
  addLine();
  addLine('  Severity     │ Count │ Percentage │ Impact');
  addLine('  ─────────────┼───────┼────────────┼──────────────');
  Object.entries(riskBreakdown).forEach(([severity, { count, percentage }]) => {
    const impact = getImpactDescription(severity);
    addLine(`  ${severity.padEnd(12)} │ ${String(count).padEnd(5)} │ ${percentage.toFixed(1).padEnd(10)}% │ ${impact}`);
  });

  // ============================================================================
  // RECOMMENDATIONS SUMMARY
  // ============================================================================
  addSection('RECOMMENDATIONS SUMMARY');
  
  if (result.recommendations && result.recommendations.length > 0) {
    addLine(`Total Recommendations: ${result.recommendations.length}`);
    addLine();
    result.recommendations.forEach((rec, index) => {
      addLine(`${index + 1}. ${rec}`);
      addLine();
    });
  } else {
    addLine('No specific recommendations at this time. Continue monitoring best practices.');
  }

  addSubsection('General Security Best Practices');
  addLine();
  addLine('1. Code Review & Audit');
  addLine('   Conduct regular security audits and peer code reviews. Engage professional');
  addLine('   security auditors for production-grade smart contracts.');
  addLine();
  addLine('2. Testing & Verification');
  addLine('   Implement comprehensive unit tests, integration tests, and fuzzing. Use formal');
  addLine('   verification methods for critical contract components.');
  addLine();
  addLine('3. Deployment Practices');
  addLine('   Deploy to testnet first. Use staged rollouts. Implement circuit breakers');
  addLine('   and pause mechanisms for emergency situations.');
  addLine();
  addLine('4. Monitoring & Incident Response');
  addLine('   Monitor contract activity in real-time. Maintain an incident response plan.');
  addLine('   Set up alerts for unusual activity patterns.');
  addLine();
  addLine('5. Documentation');
  addLine('   Maintain up-to-date documentation of contract design, architecture, and');
  addLine('   potential risk vectors. Keep a security runbook.');

  // ============================================================================
  // COMPLIANCE STATEMENT
  // ============================================================================
  addSection('COMPLIANCE STATEMENT');
  addLine();
  addLine('This audit report has been generated by an Agentic Framework that combines:');
  addLine();
  addLine('  • Static Code Analysis: Pattern-based vulnerability detection');
  addLine('  • AI-Powered Analysis: Machine learning-based semantic analysis');
  addLine('  • Standards Compliance: Verification against SWC, CWE, SCSVS, EthTrust');
  addLine('  • Confidence Scoring: Assessment of finding reliability');
  addLine();
  addLine('The audit framework follows industry standards and best practices for smart');
  addLine('contract security assessment.');

  // ============================================================================
  // DISCLAIMER & FOOTER
  // ============================================================================
  addSection('DISCLAIMER & IMPORTANT NOTICE');
  addLine();
  addLine('LIMITATION OF LIABILITY:');
  addLine('This security audit is provided as-is and represents a point-in-time');
  addLine('assessment of the smart contract code. The audit does not guarantee the');
  addLine('absence of vulnerabilities or the contract\'s fitness for any particular');
  addLine('purpose.');
  addLine();
  addLine('SCOPE AND METHODOLOGY:');
  addLine('This audit was performed using automated analysis tools combined with AI-powered');
  addLine('semantic analysis. While comprehensive, automated analysis may not detect all');
  addLine('types of vulnerabilities, particularly those requiring domain expertise or');
  addLine('business logic understanding.');
  addLine();
  addLine('RECOMMENDATIONS:');
  addLine('• This report should not be construed as financial, legal, or investment advice.');
  addLine('• All recommendations should be reviewed and tested thoroughly by qualified');
  addLine('  developers before implementation.');
  addLine('• Consider engaging multiple security firms for critical production contracts.');
  addLine('• Always follow secure development practices beyond what this audit covers.');
  addLine();
  addLine('CONFIDENTIALITY:');
  addLine('This report contains sensitive security information. It should be treated as');
  addLine('confidential and shared only with authorized personnel.');

  // ============================================================================
  // FOOTER
  // ============================================================================
  addLine();
  addLine(doubleSeparator);
  addLine();
  addLine(`Report Generated: ${new Date(result.timestamp).toLocaleString()}`);
  addLine(`Audit Framework Version: 1.0.0`);
  addLine(`Analysis Duration: ${(result.analysisTime / 1000).toFixed(2)} seconds`);
  addLine();
  addLine('For questions or concerns regarding this audit report, please review the');
  addLine('documentation or contact the audit framework administrator.');
  addLine();
  addLine(doubleSeparator);

  return lines.join('\n');
}
