import React from 'react';
import { Shield, ExternalLink, Terminal, GitBranch } from 'lucide-react';

export const Footer: React.FC = () => {
  return (
    <footer id="app-footer" className="w-full border-t border-white/[0.06] bg-[#040407] py-8 text-xs text-slate-400">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-6 h-6 rounded bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400">
              <Shield className="w-3.5 h-3.5" />
            </div>
            <div>
              <span className="font-mono font-semibold text-slate-200 tracking-tight">APKGuard</span>
              <span className="text-slate-400 text-xs ml-2">Android Banking Threat Intelligence Platform</span>
            </div>
          </div>

          {/* Center build info */}
          <div className="flex items-center gap-4 text-[11px] font-mono text-slate-400">
            <span className="flex items-center gap-1.5">
              <GitBranch className="w-3.5 h-3.5 text-slate-400" />
              <span>Model: XGBoost v1.7.4 (ROC-AUC 0.971)</span>
            </span>
            <span>•</span>
            <span className="flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-sky-400" />
              <span>Explainer: Llama 3.2 3B / Ollama</span>
            </span>
          </div>

          {/* Right Links & buildathon */}
          <div className="flex items-center gap-4 text-xs font-mono">
            <a
              id="footer-razorpay-link"
              href="https://github.com/Arsh-sudo/APKGuard"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-slate-400 hover:text-sky-400 transition-colors"
            >
              <span>Razorpay Buildathon Project</span>
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        </div>

        <div className="mt-6 pt-4 border-t border-white/[0.03] flex flex-col sm:flex-row items-center justify-between text-[11px] text-slate-400 font-mono gap-2">
          <p>Confidential & Proprietary static analysis telemetry for security operations centers (SOC) and fraud investigation units.</p>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400/80 animate-pulse"></span>
            <span>System Telemetry Nominal</span>
          </div>
        </div>
      </div>
    </footer>
  );
};
