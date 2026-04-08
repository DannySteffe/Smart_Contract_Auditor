'use client';

import { useState } from 'react';
import { AnalysisResult } from '@/types';
import { Shield, AlertTriangle, FileText, BarChart3, FileDown } from 'lucide-react';
import OverviewDashboard from '@/components/OverviewDashboard';
import VulnerabilitiesList from '@/components/VulnerabilitiesList';
import SecurityStandards from '@/components/SecurityStandards';
import AnalyticsDashboard from '@/components/AnalyticsDashboard';
import { generatePDFReport } from '@/lib/pdf-generator';

interface AnalysisResultsProps {
  result: AnalysisResult;
}

export default function AnalysisResults({ result }: AnalysisResultsProps) {
  const [activeTab, setActiveTab] = useState<'overview' | 'vulnerabilities' | 'standards' | 'analytics'>('overview');

  const tabs = [
    { id: 'overview' as const, label: 'Overview', icon: Shield },
    { id: 'vulnerabilities' as const, label: 'Vulnerabilities', icon: AlertTriangle, count: result.statistics.total },
    { id: 'standards' as const, label: 'Security Standards', icon: FileText },
    { id: 'analytics' as const, label: 'Analytics', icon: BarChart3 }
  ];

  const handleDownloadPDF = () => {
    generatePDFReport(result);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white border border-gray-200 rounded-xl p-6 shadow-md">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold mb-2 text-gray-900">Analysis Results</h1>
            <div className="flex items-center gap-3">
              <p className="text-sm text-gray-600">{result.fileName}</p>
              {result.language && (
                <span className="px-3 py-1 text-xs font-semibold rounded-full bg-gradient-to-r from-emerald-100 to-teal-100 text-emerald-800 border border-emerald-300">
                  {result.language.charAt(0).toUpperCase() + result.language.slice(1)}
                </span>
              )}
            </div>
          </div>
          <div className="flex items-center space-x-3">
            <button
              onClick={handleDownloadPDF}
              className="btn-primary flex items-center"
            >
              <FileDown className="w-4 h-4 mr-2" />
              PDF
            </button>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="bg-white border border-gray-200 rounded-xl p-6 shadow-md">
        <div className="border-b border-gray-200 mb-6">
          <div className="flex space-x-8">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center space-x-2 pb-4 border-b-2 transition-colors ${
                    activeTab === tab.id
                      ? 'border-emerald-500 text-emerald-600'
                      : 'border-transparent text-gray-500 hover:text-gray-900'
                  }`}
                >
                  <Icon className="w-5 h-5" />
                  <span className="font-semibold">{tab.label}</span>
                  {tab.count !== undefined && (
                    <span className="px-2 py-0.5 bg-red-100 text-red-600 rounded-full text-xs font-medium">
                      {tab.count}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Tab Content */}
        <div className="animate-fade-in">
          {activeTab === 'overview' && <OverviewDashboard result={result} />}
          {activeTab === 'vulnerabilities' && <VulnerabilitiesList vulnerabilities={result.vulnerabilities} />}
          {activeTab === 'standards' && <SecurityStandards result={result} />}
          {activeTab === 'analytics' && <AnalyticsDashboard result={result} />}
        </div>
      </div>
    </div>
  );
}
