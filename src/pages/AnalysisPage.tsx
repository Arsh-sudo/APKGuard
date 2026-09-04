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
  RotateCcw
} from 'lucide-react';

export const AnalysisPage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const [searchParams] = useSearchParams();
  const sampleParam = searchParams.get('sample');
  const navigate = useNavigate();

  const { activeJob, setActiveJob, addReport, addToast } = useAppStore();
  const [job, setJob] = useState<AnalysisJob | null>(activeJob);
  const [pollError, setPollError] = useState<string | null>(null);
  const [networkRetries, setNetworkRetries] = useState(0);
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

    // Handle local demo specimens
    if (jobId.startsWith('demo_') && sampleParam) {
      const specimen = mockReports.find(m => m.apk_name.toLowerCase().includes(sampleParam.toLowerCase())) || mockReports[0];

      const simulatedLogs = [
        `[${new Date().toLocaleTimeString()}] [INIT] Dispatched demo specimen: ${specimen.apk_name}`,
        `[${new Date().toLocaleTimeString()}] [ZIP] Verified PK 03 04 zip container and Dalvik headers`,
        `[${new Date().toLocaleTimeString()}] [DECOMPILE] Disassembled AndroidManifest.xml and Dalvik classes.dex`,
        `[${new Date().toLocaleTimeString()}] [PERM] Extracted ${specimen.manifest.permissions.length} declared permissions (${specimen.manifest.dangerous_permissions.length} dangerous)`,
        `[${new Date().toLocaleTimeString()}] [VECTORS] Evaluated threat feature vectors against Drebin benchmark`,
        `[${new Date().toLocaleTimeString()}] [SCORE] Risk Score: ${specimen.ml_scoring.final_score}/100 (${specimen.ml_scoring.category})`,
        `[${new Date().toLocaleTimeString()}] [LLM] Threat intelligence report and CISO brief synthesized`,
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
          message: progress < 50 ? 'Decompiling bytecode...' : progress < 80 ? 'Calculating threat feature vectors...' : 'Generating AI threat brief...',
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

    // Real server polling — no fake report generation
    const poll = async () => {
      try {
        const data = await apiService.getJobStatus(jobId);
        if (!isMounted) return;
        setPollError(null);
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
          setPollError(data.error || 'Pipeline execution failed on server.');
          addToast({
            type: 'error',
            title: 'Analysis Failed',
            message: data.error || 'The server was unable to decompile or process this APK.'
          });
        } else if (data.status === 'cancelled') {
          clearInterval(pollInterval);
        }
      } catch (err: any) {
        if (!isMounted) return;
        setNetworkRetries((prev) => {
          const next = prev + 1;
          if (next > 10) {
            clearInterval(pollInterval);
            setPollError('Network connection to analysis worker lost. Click retry to check status.');
          }
          return next;
        });
      }
    };

    poll();
    pollInterval = setInterval(poll, 1000);

    return () => {
      isMounted = false;
      clearInterval(pollInterval);
    };
  }, [jobId, sampleParam, setActiveJob, addReport, addToast]);

  const handleRetryPoll = () => {
    setPollError(null);
    setNetworkRetries(0);
    if (!jobId) return;
    apiService.getJobStatus(jobId).then((data) => {
      setJob(data);
      setActiveJob(data);
    }).catch((err) => {
      setPollError(`Could not reach server: ${err.message}`);
    });
  };

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
      if (job) setJob({ ...job, status: 'cancelled', message: 'Analysis cancelled by user' });
    }
  };

  const steps = [
    { num: 1, label: 'Ingestion & Validation', icon: Shield },
    { num: 2, label: 'Bytecode Disassembly', icon: FileCode },
    { num: 3, label: 'Threat Vector Attribution', icon: Binary },
    { num: 4, label: 'GenAI Threat Intelligence', icon: Bot },
  ];

  const currentStep = job?.current_step || 1;
  const isDone = job?.status === 'done';
  const isError = job?.status === 'error' || Boolean(pollError);
  const isCancelled = job?.status === 'cancelled';
  const isRunning = (job?.status === 'running' || job?.status === 'queued') && !isError;

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
            {job?.apk_name || 'Static Analysis Pipeline'}
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

          {isError && (
            <button
              id="retry-poll-btn"
              onClick={handleRetryPoll}
              className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] text-slate-200 border border-white/[0.08] font-mono text-xs transition-colors"
            >
              <RotateCcw className="w-4 h-4 text-sky-400" />
              <span>Retry Connection</span>
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

      {/* Error Banner */}
      {isError && (
        <div className="mb-6 p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-200 flex items-start gap-3">
          <XCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div className="text-xs font-mono">
            <span className="font-bold block uppercase tracking-wide">Analysis Failure</span>
            <p className="mt-1 text-slate-300">
              {job?.error || pollError || 'An error occurred during static analysis execution.'}
            </p>
          </div>
        </div>
      )}

      {/* Progress & Stepper Panel */}
      <div className="glass-panel rounded-2xl p-6 border border-white/[0.08] mb-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            {isRunning && <Loader2 className="w-4 h-4 text-sky-400 animate-spin" />}
            {isDone && <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
            {isError && <XCircle className="w-4 h-4 text-red-400" />}
            {isCancelled && <AlertCircle className="w-4 h-4 text-amber-400" />}
            <span className="text-xs font-mono text-slate-300 font-medium">
              {job?.message || (isError ? 'Analysis halted due to error' : 'Executing analysis pipeline...')}
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
                : 'bg-gradient-to-r from-sky-500 to-indigo-500'
            }`}
            style={{ width: `${job?.progress ?? 0}%` }}
          />
        </div>

        {/* Stepper */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {steps.map((s) => {
            const Icon = s.icon;
            const isPassed = currentStep > s.num || isDone;
            const isCurrent = currentStep === s.num && !isDone && !isError;
            const isFailed = isError && currentStep === s.num;

            let badgeClass = 'border-white/[0.08] bg-white/[0.02] text-slate-400';
            if (isPassed) {
              badgeClass = 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400';
            } else if (isCurrent) {
              badgeClass = 'border-sky-500/50 bg-sky-500/15 text-sky-300 ring-2 ring-sky-500/20';
            } else if (isFailed) {
              badgeClass = 'border-red-500/40 bg-red-500/10 text-red-300';
            }

            return (
              <div
                key={s.num}
                className={`p-3 rounded-xl border flex items-center gap-3 transition-all ${badgeClass}`}
              >
                <div className="w-8 h-8 rounded-lg bg-black/40 flex items-center justify-center shrink-0">
                  {isPassed ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  ) : isCurrent ? (
                    <Loader2 className="w-4 h-4 text-sky-400 animate-spin" />
                  ) : isFailed ? (
                    <XCircle className="w-4 h-4 text-red-400" />
                  ) : (
                    <Icon className="w-4 h-4 text-slate-400" />
                  )}
                </div>
                <div className="min-w-0">
                  <span className="text-[10px] font-mono block text-slate-400 uppercase">
                    Step 0{s.num}
                  </span>
                  <span className="text-xs font-semibold text-white block truncate">
                    {s.label}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Live Terminal Output Panel */}
      <div className="glass-panel rounded-2xl border border-white/[0.08] overflow-hidden">
        <div className="px-5 py-3 border-b border-white/[0.06] bg-white/[0.01] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-slate-400" />
            <span className="text-xs font-mono font-semibold text-slate-200">
              Live Pipeline Telemetry Output
            </span>
          </div>
          <span className="text-[10px] font-mono text-slate-400">
            {job?.logs?.length || 0} events logged
          </span>
        </div>

        <div className="p-5 font-mono text-xs text-slate-300 bg-black/50 min-h-[300px] max-h-[420px] overflow-y-auto space-y-2 select-text">
          {(!job?.logs || job.logs.length === 0) ? (
            <div className="text-slate-500 italic py-8 text-center">
              Waiting for worker process to emit execution logs...
            </div>
          ) : (
            job.logs.map((log, index) => {
              let color = 'text-slate-300';
              if (log.includes('[ERROR]')) color = 'text-red-400 font-semibold';
              else if (log.includes('[COMPLETE]')) color = 'text-emerald-400 font-semibold';
              else if (log.includes('[VECTORS]') || log.includes('[SCORE]')) color = 'text-sky-300';
              else if (log.includes('[PERM]') || log.includes('[DECOMPILE]')) color = 'text-amber-300';
              else if (log.includes('[LLM')) color = 'text-indigo-300';

              return (
                <div key={index} className={`leading-relaxed break-all ${color}`}>
                  {log}
                </div>
              );
            })
          )}
          <div ref={logsEndRef} />
        </div>
      </div>
    </div>
  );
};
