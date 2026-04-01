import jsPDF from 'jspdf';
import { AnalysisResult } from '../types';

export function generatePDFReport(result: AnalysisResult): void {
  const doc = new jsPDF({ unit: 'mm', format: 'a4' });
  const W = doc.internal.pageSize.getWidth();
  const H = doc.internal.pageSize.getHeight();

  const margin = 18;
  const contentWidth = W - margin * 2;
  const top = 18;
  const bottom = H - 16;

  let y = top;
  let pageCount = 0;

  const setFont = (size = 10, weight: 'normal' | 'bold' | 'italic' = 'normal') => {
    const style = weight === 'italic' ? 'italic' : weight;
    doc.setFont('times', style);
    doc.setFontSize(size);
    doc.setTextColor(0, 0, 0);
  };

  const startPage = (subtitle: string) => {
    if (pageCount > 0) doc.addPage();
    pageCount += 1;
    y = top;

    const rightEdge = W - margin;

    setFont(15, 'bold');
    doc.text('SMART CONTRACT SECURITY AUDIT REPORT', margin, y);

    setFont(9, 'normal');
    doc.text(subtitle, rightEdge, y, { align: 'right' });

    y += 6;
    setFont(8, 'normal');
    doc.text(`Analysis ID: ${result.analysisId}`, margin, y);
    doc.text(`Date: ${new Date(result.timestamp).toLocaleString()}`, rightEdge, y, { align: 'right' });

    y += 4;
    doc.setDrawColor(90, 90, 90);
    doc.setLineWidth(0.2);
    doc.line(margin, y, W - margin, y);
    y += 7;
  };

  const ensureSpace = (needed: number, subtitle = 'Continued') => {
    if (y + needed > bottom) {
      startPage(subtitle);
    }
  };

  const section = (title: string) => {
    ensureSpace(12);
    setFont(12, 'bold');
    doc.text(title, margin, y);
    y += 4;
    doc.setDrawColor(120, 120, 120);
    doc.setLineWidth(0.2);
    doc.line(margin, y, W - margin, y);
    y += 6;
  };

  const writeWrapped = (
    text: string,
    opts?: {
      size?: number;
      weight?: 'normal' | 'bold' | 'italic';
      indent?: number;
      lineHeight?: number;
      width?: number;
      subtitle?: string;
    },
  ) => {
    const size = opts?.size ?? 10;
    const weight = opts?.weight ?? 'normal';
    const indent = opts?.indent ?? 0;
    const lineHeight = opts?.lineHeight ?? 5.1;
    const width = opts?.width ?? (contentWidth - indent);
    const subtitle = opts?.subtitle ?? 'Continued';

    setFont(size, weight);
    const lines = doc.splitTextToSize(text || '-', width) as string[];

    lines.forEach((line) => {
      ensureSpace(lineHeight + 1, subtitle);
      doc.text(line, margin + indent, y);
      y += lineHeight;
    });
  };

  const writeKeyValue = (label: string, value: string) => {
    const labelX = margin;
    const labelWidth = 40;
    const valueX = labelX + labelWidth + 2;
    const valueText = value || '-';

    setFont(9.5, 'bold');
    const labelLines = doc.splitTextToSize(`${label}:`, labelWidth) as string[];

    setFont(9.5, 'normal');
    const valueLines = doc.splitTextToSize(valueText, W - margin - valueX) as string[];

    const rowLines = Math.max(labelLines.length, valueLines.length);
    const rowHeight = rowLines * 5 + 2;

    ensureSpace(rowHeight + 1);

    setFont(9.5, 'bold');
    doc.text(labelLines, labelX, y);

    setFont(9.5, 'normal');
    doc.text(valueLines, valueX, y);

    y += rowHeight + 1;
  };

  const summarize = (text: string, max: number) => {
    if (!text) return '-';
    return text.length > max ? `${text.slice(0, max - 3)}...` : text;
  };

  const rank: Record<string, number> = { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1 };
  const prioritized = [...result.vulnerabilities].sort((a, b) => (rank[b.severity] || 0) - (rank[a.severity] || 0));
  const failedControls = result.scsvCompliance.checklist.filter((c) => !c.passed);

  startPage('Executive Summary');

  section('1. Executive Assessment');
  writeWrapped(
    'This report presents a structured security evaluation of the smart contract. Findings are prioritized by severity, exploitability, and confidence to support remediation planning and release decisions.',
    { size: 10, lineHeight: 5.4 },
  );
  y += 3;

  section('2. Engagement Details');
  writeKeyValue('Target Contract', result.fileName);
  writeKeyValue('Language', result.language || 'Auto-detected');
  writeKeyValue('Risk Level', result.riskLevel);
  writeKeyValue('Security Score', `${result.securityScore}/100`);
  writeKeyValue('Total Findings', `${result.statistics.total}`);
  writeKeyValue('Analysis Time', `${(result.analysisTime / 1000).toFixed(2)} seconds`);
  y += 3;

  section('3. Vulnerability Breakdown');
  const total = Math.max(result.statistics.total, 1);
  const breakdown: Array<[string, number, string]> = [
    ['Critical', result.statistics.critical, 'Immediate remediation required before deployment.'],
    ['High', result.statistics.high, 'Must be closed before release approval.'],
    ['Medium', result.statistics.medium, 'Address in near-term hardening sprint.'],
    ['Low', result.statistics.low, 'Track and close through standard backlog.'],
    ['Info', result.statistics.info, 'Informational improvement opportunities.'],
  ];

  breakdown.forEach(([severity, count, note]) => {
    const share = `${Math.round((count / total) * 100)}%`;
    writeWrapped(`${severity}: ${count} (${share}) - ${note}`, { size: 9.5, lineHeight: 5 });
  });
  y += 3;

  section('4. Standards Snapshot');
  writeKeyValue(
    'SCSVS Compliance',
    `${result.scsvCompliance.percentage}% (${result.scsvCompliance.passed} passed / ${result.scsvCompliance.failed} failed)`,
  );
  writeKeyValue('EthTrust', `${result.ethTrustLevel}/5`);
  writeWrapped('Only failed SCSVS controls are listed in detail to keep this report actionable and concise.', {
    size: 9,
    lineHeight: 5,
  });

  startPage('Detailed Findings and Controls');

  section('5. Prioritized Findings');
  if (prioritized.length === 0) {
    writeWrapped('No vulnerabilities were identified in this analysis run.', { size: 10 });
  } else {
    prioritized.slice(0, 3).forEach((v, idx) => {
      ensureSpace(30);
      writeWrapped(`${idx + 1}. ${summarize(v.name, 95)}`, { size: 10.5, weight: 'bold', lineHeight: 5.4 });
      writeWrapped(
        `Severity: ${v.severity} | SWC: ${v.swcId || 'N/A'} | Line: ${v.lineNumber} | Confidence: ${v.confidence}`,
        { size: 9.2, lineHeight: 5 },
      );
      writeWrapped(`Issue: ${summarize(v.description, 240)}`, { size: 9.2, indent: 2, lineHeight: 5 });
      writeWrapped(`Recommended Fix: ${summarize(v.recommendation, 220)}`, { size: 9.2, indent: 2, lineHeight: 5 });

      y += 2;
      doc.setDrawColor(150, 150, 150);
      doc.setLineWidth(0.2);
      doc.line(margin, y, W - margin, y);
      y += 5;
    });
  }

  section('6. Failed SCSVS v2 Controls');
  if (failedControls.length === 0) {
    writeWrapped('No failed SCSVS controls detected.', { size: 10 });
  } else {
    failedControls.slice(0, 5).forEach((control, idx) => {
      ensureSpace(18);
      writeWrapped(`${idx + 1}. ${control.controlId} - ${summarize(control.title, 88)}`, {
        size: 9.6,
        weight: 'bold',
        lineHeight: 5.1,
      });

      const detail = control.findings?.[0] || 'Control failed and requires remediation evidence.';
      writeWrapped(`Detail: ${summarize(detail, 170)}`, { size: 9, indent: 2, lineHeight: 4.9 });
      y += 1;
    });
  }

  section('7. Recommended Remediation Plan');
  const actions = result.recommendations.length > 0
    ? result.recommendations.slice(0, 5)
    : [
        'Resolve all Critical and High findings before deployment approval.',
        'Re-run analysis after fixes and validate closure evidence.',
        'Treat failed controls as release blockers until verification is complete.',
      ];

  actions.forEach((action, idx) => {
    ensureSpace(10);
    writeWrapped(`${idx + 1}. ${action}`, { size: 9.5, lineHeight: 5.2 });
  });

  const pages = doc.getNumberOfPages();
  for (let p = 1; p <= pages; p++) {
    doc.setPage(p);
    doc.setDrawColor(120, 120, 120);
    doc.setLineWidth(0.2);
    doc.line(margin, H - 12, W - margin, H - 12);

    setFont(8, 'normal');
    doc.text('Confidential - SmartAudit AI Security Assessment', margin, H - 7);
    doc.text(`Page ${p} of ${pages}`, W - margin, H - 7, { align: 'right' });
  }

  const baseFileName = result.fileName.replace(/\.[^/.]+$/, '');
  doc.save(`${baseFileName}-security-report.pdf`);
}
