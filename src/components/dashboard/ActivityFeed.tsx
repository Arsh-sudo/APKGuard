import React from 'react';
import { Terminal, Shield, Cpu, Activity } from 'lucide-react';
import { mockRecentLogs } from '../../lib/mockData';

export const ActivityFeed: React.FC = () => {
  return (
    <div id="activity-feed-panel" className="glass-panel rounded-2xl p-5 border border-white/[0.08]">
      <div className="flex items-center justify-between mb-3 border-b border-white/[0.05] pb-3">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-sky-400" />
          <h3 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
            Decompiler & Model Execution Stream
          </h3>
        </div>
        <div className="flex items-center gap-1.5 text-[10px] font-mono text-emerald-400">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
          <span>LISTENING</span>
        </div>
      </div>

      <div className="bg-black/60 rounded-xl p-3 border border-white/[0.04] font-mono text-[11px] leading-relaxed text-slate-300 space-y-1.5 max-h-48 overflow-y-auto">
        {mockRecentLogs.map((log, idx) => {
          const isCritical = log.includes('CRITICAL');
          const isComplete = log.includes('COMPLETE') || log.includes('VERDICT');
          const isModel = log.includes('OLLAMA') || log.includes('XGBOOST');

          return (
            <div key={idx} className="flex items-start gap-2">
              <span className="text-slate-400 select-none">&gt;</span>
              <span
                className={`${
                  isCritical
                    ? 'text-red-400 font-semibold'
                    : isComplete
                    ? 'text-emerald-400'
                    : isModel
                    ? 'text-sky-300'
                    : 'text-slate-300'
                }`}
              >
                {log}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
};
