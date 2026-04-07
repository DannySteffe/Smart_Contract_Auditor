'use client';

import { useState } from 'react';
import Link from 'next/link';
import { Shield, Upload, Play, FileCode, ArrowLeft, Github, Code2 } from 'lucide-react';
import CodeEditor from '@/components/CodeEditor';
import AnalysisResults from '@/components/AnalysisResults';
import SampleLoader from '@/components/SampleLoader';
import AnalysisProgress from '@/components/AnalysisProgress';
import { AnalysisResult } from '@/types';

export default function AnalyzerPage() {
  const [contractCode, setContractCode] = useState('');
  const [fileName, setFileName] = useState('contract.sol');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const [githubRepoLink, setGithubRepoLink] = useState('');
  const [activeTab, setActiveTab] = useState<'paste' | 'upload'>('paste');

  const runAnalysis = async (codeToAnalyze: string, targetFileName: string): Promise<void> => {
    // Stage 1: Parsing contract
    setProgress(25);
    await new Promise(resolve => setTimeout(resolve, 250));

    // Stage 2: Static analysis - Pattern detection
    setProgress(40);
    await new Promise(resolve => setTimeout(resolve, 250));

    // Stage 3: Static analysis - SWC Registry check
    setProgress(55);

    const response = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contractCode: codeToAnalyze,
        fileName: targetFileName,
        analysisTypes: ['static', 'ai', 'standards'],
        severity: 'all'
      })
    });

    // Stage 4: Dynamic analysis - AI reasoning
    setProgress(70);
    await new Promise(resolve => setTimeout(resolve, 300));

    // Stage 5: Dynamic analysis - Logic evaluation
    setProgress(82);

    if (!response.ok) {
      const errorBody = await response.json().catch(() => null);
      throw new Error(errorBody?.error || 'Analysis failed');
    }

    const result = await response.json();

    // Stage 6: Standards compliance check
    setProgress(92);
    await new Promise(resolve => setTimeout(resolve, 200));

    // Complete
    setProgress(100);
    setAnalysisResult(result);
  };

  const handleAnalyze = async () => {
    if (!contractCode.trim()) {
      setError('Please enter contract code');
      return;
    }

    setIsAnalyzing(true);
    setError(null);
    setProgress(0);

    try {
      await runAnalysis(contractCode, fileName);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed');
    } finally {
      setIsAnalyzing(false);
      setTimeout(() => setProgress(0), 1000);
    }
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target?.result as string;
        setContractCode(content);
        setFileName(file.name);
      };
      reader.readAsText(file);
    }
  };

  const handleLoadSample = (code: string, name: string) => {
    setContractCode(code);
    setFileName(name);
    setAnalysisResult(null);
  };

  const handleGithubRepoAnalyze = async () => {
    if (!githubRepoLink.trim()) {
      setError('Please enter a GitHub repository link');
      return;
    }

    setIsAnalyzing(true);
    setError(null);
    setProgress(8);

    try {
      setProgress(15);
      const repositoryResponse = await fetch('/api/github/repository', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ githubUrl: githubRepoLink })
      });

      if (!repositoryResponse.ok) {
        const errorBody = await repositoryResponse.json().catch(() => null);
        throw new Error(errorBody?.error || 'Failed to fetch repository');
      }

      const repositoryResult = await repositoryResponse.json();
      const fetchedCode: string = repositoryResult.contractCode || '';
      const fetchedFileName: string = repositoryResult.fileName || 'contract.sol';

      if (!fetchedCode.trim()) {
        throw new Error('No smart contract files were found in this repository');
      }

      setContractCode(fetchedCode);
      setFileName(fetchedFileName);

      await runAnalysis(fetchedCode, fetchedFileName);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'GitHub repository analysis failed');
    } finally {
      setIsAnalyzing(false);
      setTimeout(() => setProgress(0), 1000);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Navigation */}
      <nav className="border-b border-gray-200 bg-white/80 backdrop-blur-lg sticky top-0 z-50 shadow-sm">
        <div className="container mx-auto px-4">
          <div className="flex items-center justify-between h-16">
            <Link href="/" className="flex items-center space-x-2">
              <ArrowLeft className="w-5 h-5 text-gray-600 hover:text-emerald-600" />
              <Shield className="w-8 h-8 text-emerald-500" />
              <span className="text-xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-emerald-500 to-teal-500">SmartAudit AI</span>
            </Link>
            <div className="flex items-center space-x-4">
              <span className="text-sm text-gray-600 font-medium">{fileName}</span>
            </div>
          </div>
        </div>
      </nav>

      <div className="container mx-auto px-4 py-8">
        {!analysisResult ? (
          <div className="grid lg:grid-cols-3 gap-6">
            {/* Code Input Section */}
            <div className="lg:col-span-2 space-y-6">
              <div className="card">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-2xl font-bold flex items-center text-gray-900">
                    <FileCode className="w-6 h-6 mr-2 text-emerald-600" />
                    Smart Contract Code
                  </h2>
                </div>

                {/* File Name Input */}
                <div className="mb-4">
                  <label className="block text-sm font-semibold text-gray-700 mb-2">
                    <FileCode className="w-4 h-4 inline mr-2" />
                    Contract Name
                  </label>
                  <input
                    type="text"
                    value={fileName}
                    onChange={(e) => setFileName(e.target.value)}
                    placeholder="contract.sol / contract.vy / contract.cairo"
                    className="w-full px-4 py-2 border-2 border-gray-300 rounded-lg focus:outline-none focus:border-emerald-500 text-gray-900"
                  />
                </div>

                {/* GitHub Repo Input */}
                <div className="mb-4">
                  <label className="block text-sm font-semibold text-gray-700 mb-2">
                    <Github className="w-4 h-4 inline mr-2" />
                    GitHub Repository Link
                  </label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={githubRepoLink}
                      onChange={(e) => setGithubRepoLink(e.target.value)}
                      placeholder="https://github.com/username/repo"
                      className="flex-1 px-4 py-2 border-2 border-gray-300 rounded-lg focus:outline-none focus:border-emerald-500 text-gray-900"
                    />
                    <button
                      onClick={handleGithubRepoAnalyze}
                      disabled={isAnalyzing || !githubRepoLink.trim()}
                      className="px-6 py-2 bg-emerald-500 hover:bg-emerald-600 text-white font-semibold rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      Analyze
                    </button>
                  </div>
                </div>

                {/* Tabs */}
                <div className="flex gap-2 mb-4 border-b border-gray-200">
                  <button
                    onClick={() => setActiveTab('paste')}
                    className={`flex items-center px-6 py-3 font-semibold transition-all border-b-2 ${activeTab === 'paste'
                        ? 'border-blue-500 text-blue-600'
                        : 'border-transparent text-gray-500 hover:text-gray-700'
                      }`}
                  >
                    <Code2 className="w-4 h-4 mr-2" />
                    Paste Code
                  </button>
                  <button
                    onClick={() => setActiveTab('upload')}
                    className={`flex items-center px-6 py-3 font-semibold transition-all border-b-2 ${activeTab === 'upload'
                        ? 'border-blue-500 text-blue-600'
                        : 'border-transparent text-gray-500 hover:text-gray-700'
                      }`}
                  >
                    <Upload className="w-4 h-4 mr-2" />
                    Upload File
                  </button>
                </div>

                {/* Paste Code Tab */}
                {activeTab === 'paste' && (
                  <div>
                    <textarea
                      value={contractCode}
                      onChange={(e) => setContractCode(e.target.value)}
                      placeholder={`Paste your code here...

Example:
pragma solidity ^0.8.0;

contract UserAuth {
    mapping(address => bool) public isRegistered;

    function registerUser() public {
        require(!isRegistered[msg.sender], 'User already registered');
        isRegistered[msg.sender] = true;
    }
}`}
                      className="w-full h-96 px-4 py-3 border-2 border-gray-300 rounded-lg focus:outline-none focus:border-emerald-500 font-mono text-sm text-gray-700 resize-none leading-relaxed"
                    />
                    <div className="mt-2 text-sm text-blue-600">
                      {contractCode.split('\n').length} lines • {contractCode.length} characters
                    </div>
                  </div>
                )}

                {/* Upload File Tab */}
                {activeTab === 'upload' && (
                  <div className="border-2 border-dashed border-gray-300 rounded-lg p-12 text-center">
                    <Upload className="w-12 h-12 mx-auto mb-4 text-gray-400" />
                    <label className="cursor-pointer">
                      <span className="text-blue-600 hover:text-blue-700 font-semibold">Click to upload</span>
                      <span className="text-gray-500"> or drag and drop</span>
                      <input
                        type="file"
                        accept=".sol,.vy,.cairo"
                        onChange={handleFileUpload}
                        className="hidden"
                      />
                    </label>
                    <p className="text-xs text-gray-500 mt-2">Solidity (.sol), Vyper (.vy), or Cairo (.cairo) files</p>
                  </div>
                )}

                {error && (
                  <div className="mt-4 p-4 bg-red-50 border border-red-300 rounded-lg text-red-700">
                    {error}
                  </div>
                )}

                <button
                  onClick={handleAnalyze}
                  disabled={isAnalyzing || !contractCode.trim()}
                  className="btn-primary w-full mt-4 flex items-center justify-center disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isAnalyzing ? (
                    <>
                      <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin mr-2" />
                      Analyzing...
                    </>
                  ) : (
                    <>
                      <Play className="w-5 h-5 mr-2" />
                      Analyze Contract
                    </>
                  )}
                </button>

                {isAnalyzing && <AnalysisProgress progress={progress} />}
              </div>
            </div>

            {/* Sidebar */}
            <div className="space-y-6">
              <SampleLoader onLoad={handleLoadSample} />

              <div className="card">
                <h3 className="text-lg font-bold mb-4 text-gray-900">Analysis Features</h3>
                <ul className="space-y-3 text-sm text-gray-600">
                  <li className="flex items-start">
                    <div className="w-2 h-2 bg-blue-500 rounded-full mt-1.5 mr-2 flex-shrink-0" />
                    <span><strong>Static Analysis:</strong> Pattern-based vulnerability detection using SWC Registry</span>
                  </li>
                  <li className="flex items-start">
                    <div className="w-2 h-2 bg-purple-500 rounded-full mt-1.5 mr-2 flex-shrink-0" />
                    <span><strong>Dynamic Analysis:</strong> AI-powered deep analysis of complex logic and business rules</span>
                  </li>
                  <li className="flex items-start">
                    <div className="w-2 h-2 bg-green-500 rounded-full mt-1.5 mr-2 flex-shrink-0" />
                    <span>SCSVS v2 compliance checking</span>
                  </li>
                  <li className="flex items-start">
                    <div className="w-2 h-2 bg-orange-500 rounded-full mt-1.5 mr-2 flex-shrink-0" />
                    <span>EthTrust security level assessment</span>
                  </li>
                </ul>
              </div>

              <div className="card bg-blue-50/50 border-blue-200">
                <h3 className="text-lg font-bold mb-2 text-gray-900">Security Standards</h3>
                <p className="text-sm text-gray-600 mb-3">
                  Analysis based on industry-recognized frameworks
                </p>
                <div className="space-y-2 text-xs">
                  <div className="flex justify-between">
                    <span className="text-gray-600">SWC Registry</span>
                    <span className="text-blue-600 font-semibold">35+ Checks</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">SCSVS v2</span>
                    <span className="text-purple-600 font-semibold">50+ Controls</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">EthTrust</span>
                    <span className="text-green-600 font-semibold">5 Levels</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div>
            <button
              onClick={() => setAnalysisResult(null)}
              className="mb-6 btn-secondary flex items-center"
            >
              <ArrowLeft className="w-4 h-4 mr-2" />
              New Analysis
            </button>
            <AnalysisResults result={analysisResult} />
          </div>
        )}
      </div>
    </div>
  );
}
