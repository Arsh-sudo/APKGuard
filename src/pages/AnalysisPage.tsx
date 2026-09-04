import React, { useEffect, useState, useRef } from 'react';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import { AnalysisJob, APKReport } from '../types';
import { apiService } from '../lib/api';
import { useAppStore } from '../lib/store';
import { mockReports } from '../lib/mockData';
import {
  FileCode,
  Binary,
  Bot,
  CheckCircle2,
  AlertCircle,
  XCircle,
  Terminal,
  ArrowRight,
  Shield,
  Loader2,
  StopCircle,
  Clock
} from 'lucide-react';

export const AnalysisPage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const [searchParams] = useSearchParams();
  const sampleParam = searchParams.get('sample');
  const navigate = useNavigate();

  const { activeJob, setActiveJob, addReport, addToast } = useAppStore();
  const [job, setJob] = useState<AnalysisJob | null>(activeJob);
  const [pollError, setPollError] = useState<string | null>(null);
  const logsEndRef = useRef<HTMLDivElement | null>(null);

  // Auto-scroll logs
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [job?.logs]);

  // Polling logic
  useEffect(() => {
    if (!jobId) return;

    let isMounted = true;
    let pollInterval: any = null;

    // Handle mock demo specimens
    if (jobId.startsWith('demo_') && sampleParam) {
      const specimen = mockReports.find(m => m.apk_name.toLowerCase().includes(sampleParam.toLowerCase())) || mockReports[0];

      const simulatedLogs = [
        `[${new Date().toLocaleTimeString()}] [INIT] Dispatched demo specimen: ${specimen.apk_name}`,
        `[${new Date().toLocaleTimeString()}] [ZIP] Verified PK 03 04 zip container`,
        `[${new Date().toLocaleTimeString()}] [DECOMPILE] Disassembled AndroidManifest.xml and Dalvik classes.dex`,
        `[${new Date().toLocaleTimeString()}] [PERM] Extracted ${specimen.manifest.permissions.length} declared permissions (${specimen.manifest.dangerous_permissions.length} dangerous)`,
        `[${new Date().toLocaleTimeString()}] [XGBOOST] Evaluated 330-feature permission vector against Drebin model`,
        `[${new Date().toLocaleTimeString()}] [SCORE] Risk Score: ${specimen.ml_scoring.final_score}/100 (${specimen.ml_scoring.category})`,
        `[${new Date().toLocaleTimeString()}] [LLM] Llama 3.2 synthesized threat narrative and CISO brief`,
        `[${new Date().toLocaleTimeString()}] [COMPLETE] Report generated successfully.`
      ];

      let step = 1;
      let progress = 20;

      pollInterval = setInterval(() => {
        if (!isMounted) return;
        progress += 20;
        if (progress === 40) step = 2;
        if (progress === 70) step = 3;
        if (progress >= 100) {
          clearInterval(pollInterval);
          const doneJob: AnalysisJob = {
            job_id: jobId,
            apk_name: specimen.apk_name,
            original_name: specimen.apk_name,
            status: 'done',
            progress: 100,
            current_step: 4,
            message: 'Analysis complete',
            logs: simulatedLogs,
            result: specimen,
            error: null,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          };
          setJob(doneJob);
          setActiveJob(doneJob);
          addReport(specimen);
          return;
        }

        const updated: AnalysisJob = {
          job_id: jobId,
          apk_name: specimen.apk_name,
          original_name: specimen.apk_name,
          status: 'running',
          progress,
          current_step: step,
          message: progress < 50 ? 'Decompiling bytecode...' : progress < 80 ? 'XGBoost feature scoring...' : 'Generating AI threat brief...',
          logs: simulatedLogs.slice(0, Math.floor((progress / 100) * simulatedLogs.length) + 1),
          result: null,
          error: null,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        };
        setJob(updated);
        setActiveJob(updated);
      }, 700);

      return () => {
        isMounted = false;
        clearInterval(pollInterval);
      };
    }

    // Real server polling
    const poll = async () => {
      try {
        const data = await apiService.getJobStatus(jobId);
        if (!isMounted) return;
        setJob(data);
        setActiveJob(data);

        if (data.status === 'done' && data.result) {
          clearInterval(pollInterval);
          addReport(data.result);
          addToast({
            type: 'success',
            title: 'Analysis Finished',
            message: `Report ready for ${data.result.apk_name}`
          });
        } else if (data.status === 'error') {
          clearInterval(pollInterval);
          setPollError(data.error || 'Pipeline execution failed');
        } else if (data.status === 'cancelled') {
          clearInterval(pollInterval);
        }
      } catch (err: any) {
        if (!isMounted) return;
        setPollError(err.message || 'Error polling job');
      }
    };

    poll();
    pollInterval = setInterval(poll, 750);

    return () => {
      isMounted = false;
      clearInterval(pollInterval);
    };
  }, [jobId, sampleParam, setActiveJob, addReport, addToast]);

  const handleCancel = async () => {
    if (!jobId) return;
    try {
      await apiService.cancelJob(jobId);
      addToast({
        type: 'warning',
        title: 'Job Aborted',
        message: 'Analysis pipeline halted by user.'
      });
      if (job) {
        setJob({ ...job, status: 'cancelled', message: 'Analysis cancelled by user' });
      }
    } catch {
      // local cancel fallback
      if (job) setJob({ ...job, status: 'cancelled', message: 'Analysis cancelled by user' });
    }
  };

  const steps = [
    { num: 1, label: 'Ingestion & Validation', icon: Shield },
    { num: 2, label: 'Bytecode Disassembly', icon: FileCode },
    { num: 3, label: 'XGBoost ML Scoring', icon: Binary },
    { num: 4, label: 'GenAI Threat Intelligence', icon: Bot },
  ];

  const currentStep = job?.current_step || 1;
  const isDone = job?.status === 'done';
  const isError = job?.status === 'error';
  const isCancelled = job?.status === 'cancelled';
  const isRunning = job?.status === 'running' || job?.status === 'queued';

  return (
    <div className="min-h-screen py-10 px-4 sm:px-6 lg:px-8 max-w-5xl mx-auto">
      {/* Top Breadcrumb & Job ID Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400 mb-1">
            <span>PIPELINE EXECUTION</span>
            <span>/</span>
            <span className="text-sky-400">JOB #{jobId}</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-white font-sans tracking-tight">
            {job?.apk_name || 'Static Analysis in Progress'}
          </h1>
        </div>

        <div className="flex items-center gap-3">
          {isRunning && (
            <button
              id="cancel-job-btn"
              onClick={handleCancel}
              className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-300 border border-red-500/30 font-mono text-xs transition-colors"
            >
              <StopCircle className="w-4 h-4" />
              <span>Cancel Job</span>
            </button>
          )}

          {isDone && job?.result && (
            <button
              id="view-report-now-btn"
              onClick={() => navigate(`/report/${job.result?.apk_name}`)}
              className="flex items-center gap-2 px-5 py-2 rounded-xl bg-sky-500 hover:bg-sky-400 text-slate-950 font-mono font-bold text-xs uppercase tracking-wider transition-all shadow-lg shadow-sky-500/25 animate-pulse"
            >
              <span>View Threat Report</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      {/* Progress & Stepper Panel */}
      <div className="glass-panel rounded-2xl p-6 border border-white/[0.08] mb-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            {isRunning && <Loader2 className="w-4 h-4 text-sky-400 animate-spin" />}
            {isDone && <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
            {isError && <XCircle className="w-4 h-4 text-red-400" />}
            {isCancelled && <AlertCircle className="w-4 h-4 text-amber-400" />}
            <span className="text-xs font-mono text-slate-300 font-medium">
              {job?.message || 'Executing analysis pipeline...'}
            </span>
          </div>
          <span className="text-sm font-mono font-bold text-white">
            {job?.progress ?? 0}%
          </span>
        </div>

        {/* Linear progress bar */}
        <div className="w-full h-2 rounded-full bg-white/[0.06] overflow-hidden mb-6">
          <div
            className={`h-full transition-all duration-500 ease-out ${
              isError
                ? 'bg-red-500'
                : isCancelled
                ? 'bg-amber-500'
                : isDone
                ? 'bg-emerald-400'
                : 'bg-sky-400'
            }`}
            style={{ width: `${job?.progress ?? 5}%` }}
          />
        </div>

        {/* 4 Steps Indicator */}
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 pt-2 border-t border-white/[0.05]">
          {steps.map((step) => {
            const Icon = step.icon;
            const completed = currentStep > step.num || isDone;
            const active = currentStep === step.num && !isDone;

            return (
              <div
                key={step.num}
                className={`p-3 rounded-xl border flex items-center gap-3 transition-all ${
                  completed
                    ? 'bg-emerald-500/5 border-emerald-500/20 text-emerald-400'
                    : active
                    ? 'bg-sky-500/10 border-sky-500/30 text-sky-300 shadow-sm shadow-sky-950'
                    : 'bg-white/[0.01] border-white/[0.04] text-slate-400'
                }`}
              >
                <div
                  className={`w-7 h-7 rounded-lg flex items-center justify-center font-mono text-xs font-bold ${
                    completed
                      ? 'bg-emerald-500/20 text-emerald-300'
                      : active
                      ? 'bg-sky-500/20 text-sky-300 animate-pulse'
                      : 'bg-white/[0.04] text-slate-400'
                  }`}
                >
                  {completed ? <CheckCircle2 className="w-4 h-4" /> : step.num}
                </div>
                <div className="min-w-0">
                  <span className="text-[11px] font-mono font-semibold block truncate">
                    {step.label}
                  </span>
                  <span className="text-[10px] text-slate-400 font-sans block">
                    {completed ? 'Completed' : active ? 'Processing...' : 'Waiting'}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Live Terminal Console */}
      <div className="glass-panel rounded-2xl border border-white/[0.08] overflow-hidden">
        <div className="px-5 py-3 border-b border-white/[0.06] bg-black/40 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-sky-400" />
            <span className="text-xs font-mono font-bold text-slate-200">
              TELEMETRY LOG STREAM (stdout/stderr)
            </span>
          </div>
          <div className="flex items-center gap-2 text-[10px] font-mono text-slate-400">
            <Clock className="w-3 h-3 text-slate-400" />
            <span>Real-time bytecode parser</span>
          </div>
        </div>

        <div className="p-4 bg-black/85 font-mono text-xs leading-relaxed text-slate-300 max-h-96 overflow-y-auto space-y-1">
          {job?.logs && job.logs.length > 0 ? (
            job.logs.map((line, idx) => {
              const isCrit = line.includes('CRITICAL') || line.includes('ERROR');
              const isSuccess = line.includes('COMPLETE') || line.includes('done') || line.includes('Verified');
              const isNotice = line.includes('XGBOOST') || line.includes('LLM');

              return (
                <div key={idx} className="flex items-start gap-2">
                  <span className="text-slate-400 select-none text-[11px]">&gt;</span>
                  <span
                    className={`${
                      isCrit
                        ? 'text-red-400 font-semibold'
                        : isSuccess
                        ? 'text-emerald-400'
                        : isNotice
                        ? 'text-sky-300'
                        : 'text-slate-300'
                    }`}
                  >
                    {line}
                  </span>
                </div>
              );
            })
          ) : (
            <div className="text-slate-400 italic">Initializing execution worker...</div>
          )}
          <div ref={logsEndRef} />
        </div>
      </div>

      {/* Failure or Cancel Notice */}
      {(isError || isCancelled) && (
        <div className="mt-6 p-4 rounded-xl border border-red-500/30 bg-red-500/10 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <XCircle className="w-5 h-5 text-red-400" />
            <div>
              <h4 className="text-sm font-semibold text-white font-mono">
                {isCancelled ? 'Analysis Job Aborted' : 'Pipeline Execution Failed'}
              </h4>
              <p className="text-xs text-red-200/80 mt-0.5 font-sans">
                {job?.error || pollError || 'Execution was halted before completion.'}
              </p>
            </div>
          </div>
          <button
            onClick={() => navigate('/dashboard')}
            className="px-3.5 py-1.5 rounded-lg bg-white/[0.08] hover:bg-white/[0.15] text-white font-mono text-xs"
          >
            Return to Dashboard
          </button>
        </div>
      )}
    </div>
  );
};
