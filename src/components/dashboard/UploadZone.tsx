import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Upload, FileCode, Sparkles, CheckCircle2, AlertCircle, ArrowRight, ShieldCheck, Play } from 'lucide-react';
import { useAppStore } from '../../lib/store';
import { apiService } from '../../lib/api';

export const UploadZone: React.FC = () => {
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const { useLLM, setUseLLM, addToast, setActiveJob } = useAppStore();

  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const validateAndSetFile = (file: File) => {
    if (!file.name.toLowerCase().endsWith('.apk')) {
      addToast({
        type: 'error',
        title: 'Invalid File Extension',
        message: 'APKGuard only processes compiled Android application packages (.apk).'
      });
      return false;
    }

    if (file.size > 100 * 1024 * 1024) {
      addToast({
        type: 'error',
        title: 'Payload Exceeds Limit',
        message: 'Max file size is 100MB for static bytecode decomposition.'
      });
      return false;
    }

    setSelectedFile(file);
    return true;
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const handleStartAnalysis = async () => {
    if (!selectedFile) return;

    setIsSubmitting(true);
    try {
      addToast({
        type: 'info',
        title: 'Dispatching APK Package',
        message: `Uploading ${selectedFile.name} to analysis engine...`
      });

      const { job_id } = await apiService.uploadAndAnalyse(selectedFile, useLLM);

      // Pre-seed local job in store for immediate reactive transition
      setActiveJob({
        job_id,
        apk_name: selectedFile.name,
        original_name: selectedFile.name,
        status: 'running',
        progress: 15,
        current_step: 1,
        message: 'Validating APK container & decompiling Dalvik bytecode...',
        logs: [
          `[${new Date().toLocaleTimeString()}] [INIT] Dispatched ${selectedFile.name} (${(selectedFile.size / 1024).toFixed(1)} KB)`,
          `[${new Date().toLocaleTimeString()}] [ZIP] Verified zip structure and Dalvik manifest headers`
        ],
        result: null,
        error: null,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      });

      navigate(`/analysis/${job_id}`);
    } catch (err: any) {
      addToast({
        type: 'error',
        title: 'Analysis Launch Failed',
        message: err.message || 'Could not queue analysis task'
      });
      setIsSubmitting(false);
    }
  };

  const handleQuickDemo = (sampleName: string) => {
    // Generate simulated job
    const fakeJobId = 'demo_' + Math.random().toString(36).substring(2, 10);
    setActiveJob({
      job_id: fakeJobId,
      apk_name: sampleName,
      original_name: sampleName,
      status: 'running',
      progress: 25,
      current_step: 2,
      message: 'Decompiling package and extracting permissions...',
      logs: [
        `[${new Date().toLocaleTimeString()}] [DEMO] Ingesting verified dataset specimen: ${sampleName}`,
        `[${new Date().toLocaleTimeString()}] [DECOMPILE] apktool disassembled classes.dex (640 smali files)`,
        `[${new Date().toLocaleTimeString()}] [XGBOOST] Vectorizing 330 permission and API features...`
      ],
      result: null,
      error: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });
    navigate(`/analysis/${fakeJobId}?sample=${encodeURIComponent(sampleName)}`);
  };

  return (
    <div id="upload-zone-container" className="glass-panel rounded-2xl p-6 border border-white/[0.08] relative overflow-hidden">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-6">
        <div>
          <h2 className="text-lg font-bold text-white font-sans flex items-center gap-2">
            <span>APK Static Threat Analyzer</span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/20">
              100MB Limit
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Drag & drop compiled Android APK or test verified banking threat specimens.
          </p>
        </div>

        {/* AI Explainer Option */}
        <div className="flex items-center gap-2.5 px-3 py-1.5 rounded-lg bg-white/[0.02] border border-white/[0.06]">
          <Sparkles className={`w-4 h-4 ${useLLM ? 'text-sky-400' : 'text-slate-500'}`} />
          <div className="text-left">
            <span className="text-xs font-mono text-slate-200 block font-medium">Generate AI Threat Brief</span>
            <span className="text-[10px] text-slate-400 block font-sans">Llama 3.2 CISO explanation</span>
          </div>
          <input
            id="llm-toggle-checkbox"
            type="checkbox"
            checked={useLLM}
            onChange={(e) => setUseLLM(e.target.checked)}
            className="w-4 h-4 rounded bg-slate-900 border-white/20 text-sky-600 focus:ring-0 cursor-pointer ml-1"
          />
        </div>
      </div>

      {/* Drag & Drop Target Area */}
      <div
        id="drop-area"
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`relative border-2 border-dashed rounded-xl p-8 sm:p-12 text-center transition-all cursor-pointer group ${
          dragActive
            ? 'border-sky-400 bg-sky-500/10 shadow-lg shadow-sky-950/50'
            : selectedFile
            ? 'border-emerald-500/40 bg-emerald-500/5'
            : 'border-white/[0.12] hover:border-white/[0.25] bg-white/[0.01] hover:bg-white/[0.03]'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".apk"
          onChange={handleFileChange}
          className="hidden"
          id="apk-file-input"
        />

        {selectedFile ? (
          <div className="flex flex-col items-center">
            <div className="w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 mb-3 shadow-md shadow-emerald-950">
              <CheckCircle2 className="w-6 h-6" />
            </div>
            <h3 className="text-sm font-mono font-bold text-white tracking-tight">
              {selectedFile.name}
            </h3>
            <span className="text-xs text-slate-400 font-mono mt-1">
              {(selectedFile.size / 1024 / 1024).toFixed(2)} MB • Ready for decomposition
            </span>
            <p className="text-[11px] text-slate-400 mt-2 font-sans">
              Click to replace or launch analysis below.
            </p>
          </div>
        ) : (
          <div className="flex flex-col items-center">
            <div className="w-12 h-12 rounded-xl bg-sky-500/10 border border-sky-500/20 flex items-center justify-center text-sky-400 mb-3 group-hover:scale-105 transition-transform">
              <Upload className="w-6 h-6" />
            </div>
            <h3 className="text-sm font-semibold text-white tracking-tight">
              Drag your .apk binary here, or <span className="text-sky-400 underline">browse</span>
            </h3>
            <p className="text-xs text-slate-400 mt-1 font-sans max-w-sm">
              Magic header validated (PK\x03\x04). Dalvik bytecode, manifest, and resources are extracted safely in memory.
            </p>
          </div>
        )}
      </div>

      {/* Start Button & Samples */}
      <div className="mt-5 flex flex-col sm:flex-row items-center justify-between gap-4">
        {/* Quick Demo Test Pills */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider flex items-center gap-1">
            <Play className="w-3 h-3 text-sky-400" />
            <span>Test Specimens:</span>
          </span>
          <button
            id="demo-trojan-btn"
            type="button"
            onClick={() => handleQuickDemo('BankingTrojan-Hydra.apk')}
            className="text-[11px] font-mono px-2.5 py-1 rounded bg-red-500/10 text-red-300 border border-red-500/30 hover:bg-red-500/20 transition-colors"
          >
            Hydra Banking Trojan (Critical)
          </button>
          <button
            id="demo-loan-btn"
            type="button"
            onClick={() => handleQuickDemo('QuickCredit-FastLoan.apk')}
            className="text-[11px] font-mono px-2.5 py-1 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30 hover:bg-amber-500/20 transition-colors"
          >
            Predatory Loan Extortion (Critical)
          </button>
          <button
            id="demo-clean-btn"
            type="button"
            onClick={() => handleQuickDemo('GoogleCalculator-v8.1.apk')}
            className="text-[11px] font-mono px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/20 transition-colors"
          >
            Google Calculator (Low Risk)
          </button>
        </div>

        {/* Main CTA */}
        {selectedFile && (
          <button
            id="start-analysis-btn"
            disabled={isSubmitting}
            onClick={handleStartAnalysis}
            className="w-full sm:w-auto flex items-center justify-center gap-2 px-6 py-2.5 rounded-xl bg-sky-500 hover:bg-sky-400 text-slate-950 font-mono font-bold text-xs uppercase tracking-wider transition-all shadow-lg shadow-sky-500/25 disabled:opacity-50"
          >
            {isSubmitting ? 'Ingesting Payload...' : 'Start Threat Pipeline'}
            <ArrowRight className="w-4 h-4" />
          </button>
        )}
      </div>
    </div>
  );
};
