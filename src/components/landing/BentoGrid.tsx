import React, { useState } from 'react';
import { bentoBenchmarkData } from '../../lib/mockData';
import { BarChart3, Sliders, AlertOctagon, TrendingUp, Cpu, ShieldCheck, Check, Layers, Info } from 'lucide-react';

export const BentoGrid: React.FC = () => {
  const [activeThreshold, setActiveThreshold] = useState<number>(0.80);

  const activeRow = bentoBenchmarkData.thresholdTable.find(t => t.threshold === activeThreshold) || bentoBenchmarkData.thresholdTable[2];

  return (
    <section id="bento-benchmarks-section" className="py-20 border-t border-white/[0.05] bg-[#06060c]/60 relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto mb-14">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-mono mb-4">
            <TrendingUp className="w-3.5 h-3.5" />
            <span>EMPIRICAL BENCHMARKS & MODEL ARCHITECTURE</span>
          </div>
          <h2 className="text-2xl sm:text-3xl lg:text-4xl font-bold text-white tracking-tight font-sans">
            Engineered for Bank Perimeters, Not Just Test Sets
          </h2>
          <p className="mt-3 text-slate-400 text-sm sm:text-base leading-relaxed">
            Standard models trigger catastrophic false positive floods in production. APKGuard calibrates
            XGBoost at an optimal 0.80 operating threshold to safeguard SOC efficiency.
          </p>
        </div>

        {/* Bento Grid layout */}
        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-5">
          {/* Card 1: Key Performance Indicators */}
          <div className="md:col-span-2 glass-panel rounded-xl p-6 border border-white/[0.08] relative overflow-hidden flex flex-col justify-between">
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs font-mono text-sky-400 uppercase tracking-wider flex items-center gap-1.5">
                <BarChart3 className="w-4 h-4" />
                <span>Core Model Performance</span>
              </span>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-sky-500/10 text-sky-300 border border-sky-500/20">
                Drebin Dataset
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 my-4">
              <div className="p-3 rounded-lg bg-white/[0.02] border border-white/[0.05]">
                <div className="text-3xl sm:text-4xl font-mono font-bold text-white tracking-tight text-emerald-400">
                  {bentoBenchmarkData.rocAuc}
                </div>
                <div className="text-xs font-sans text-slate-400 mt-1 font-medium">ROC-AUC Score</div>
                <div className="text-[10px] font-mono text-emerald-500/80 mt-0.5">Top-tier discrimination</div>
              </div>

              <div className="p-3 rounded-lg bg-white/[0.02] border border-white/[0.05]">
                <div className="text-3xl sm:text-4xl font-mono font-bold text-white tracking-tight text-sky-400">
                  {bentoBenchmarkData.f1Score}
                </div>
                <div className="text-xs font-sans text-slate-400 mt-1 font-medium">F1 Score (Balanced)</div>
                <div className="text-[10px] font-mono text-sky-500/80 mt-0.5">Harmonic precision/recall</div>
              </div>

              <div className="p-3 rounded-lg bg-white/[0.02] border border-white/[0.05]">
                <div className="text-3xl sm:text-4xl font-mono font-bold text-white tracking-tight text-white">
                  {bentoBenchmarkData.totalFeatures}
                </div>
                <div className="text-xs font-sans text-slate-400 mt-1 font-medium">Feature Dimension</div>
                <div className="text-[10px] font-mono text-slate-400 mt-0.5">Permissions & APIs</div>
              </div>

              <div className="p-3 rounded-lg bg-white/[0.02] border border-white/[0.05]">
                <div className="text-3xl sm:text-4xl font-mono font-bold text-white tracking-tight text-amber-400">
                  1.4%
                </div>
                <div className="text-xs font-sans text-slate-400 mt-1 font-medium">False Positive Rate</div>
                <div className="text-[10px] font-mono text-amber-500/80 mt-0.5">At 0.80 threshold</div>
              </div>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              Trained on banking-focused malware subsets and benign utility binaries. Bytecode feature vectors
              are scored with tree-based boosting to reveal subtle API abuse patterns invisible to traditional signature hashes.
            </p>
          </div>

          {/* Card 2: Interactive Threshold Sweeper */}
          <div className="md:col-span-1 lg:col-span-2 glass-panel rounded-xl p-6 border border-white/[0.08] flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-mono text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Sliders className="w-4 h-4" />
                  <span>Operating Point Analysis</span>
                </span>
                <span className="text-[11px] font-mono text-slate-400">
                  Selected: <strong className="text-amber-400 font-bold">{activeThreshold.toFixed(2)}</strong>
                </span>
              </div>

              <p className="text-xs text-slate-400 mb-4">
                Click an operating threshold to view how precision, recall, and false positive rates adjust:
              </p>

              {/* Threshold buttons */}
              <div className="grid grid-cols-4 gap-2 mb-4">
                {bentoBenchmarkData.thresholdTable.map((item) => (
                  <button
                    key={item.threshold}
                    id={`threshold-btn-${item.threshold}`}
                    onClick={() => setActiveThreshold(item.threshold)}
                    className={`py-2 px-2 text-center rounded-lg font-mono text-xs transition-all border ${
                      activeThreshold === item.threshold
                        ? 'bg-amber-500/20 text-amber-300 border-amber-500/40 shadow-sm shadow-amber-950'
                        : 'bg-white/[0.02] text-slate-400 border-white/[0.05] hover:bg-white/[0.05] hover:text-white'
                    }`}
                  >
                    <div className="font-bold">τ = {item.threshold.toFixed(2)}</div>
                    {item.threshold === 0.80 && (
                      <span className="text-[9px] text-amber-400 font-sans block">Optimal</span>
                    )}
                  </button>
                ))}
              </div>

              {/* Dynamic metrics for selected threshold */}
              <div className="p-3.5 rounded-lg bg-black/40 border border-white/[0.06] grid grid-cols-3 gap-3 text-center">
                <div>
                  <div className="text-xs text-slate-400 font-sans">Precision</div>
                  <div className="text-lg font-mono font-bold text-white mt-0.5">
                    {(activeRow.precision * 100).toFixed(1)}%
                  </div>
                </div>
                <div>
                  <div className="text-xs text-slate-400 font-sans">Recall</div>
                  <div className="text-lg font-mono font-bold text-sky-400 mt-0.5">
                    {(activeRow.recall * 100).toFixed(1)}%
                  </div>
                </div>
                <div>
                  <div className="text-xs text-slate-400 font-sans">False Positives</div>
                  <div className="text-lg font-mono font-bold text-red-400 mt-0.5">
                    {activeRow.fpr}
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-white/[0.05] text-[11px] font-mono text-slate-400 flex items-center gap-1.5">
              <Info className="w-3.5 h-3.5 text-amber-400 shrink-0" />
              <span>Default 0.50 threshold yields 6.2% FPR — too noisy for commercial banking apps.</span>
            </div>
          </div>

          {/* Card 3: Base-Rate Fallacy Projection */}
          <div className="md:col-span-3 lg:col-span-2 glass-panel rounded-xl p-6 border border-white/[0.08]">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-mono text-red-400 uppercase tracking-wider flex items-center gap-1.5">
                <AlertOctagon className="w-4 h-4" />
                <span>Base-Rate Fallacy in Real-World Streams</span>
              </span>
              <span className="text-[11px] font-mono text-slate-400">Real-World Prevalence</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed mb-4">
              In laboratory testing, malware prevalence is artificially set to 50%. In enterprise app stores,
              banking malware prevalence drops below 0.1%. At 0.1%, a 1.4% false positive rate still generates
              hundreds of false alarms:
            </p>

            <div className="space-y-2 font-mono text-xs">
              {bentoBenchmarkData.prevalenceData.map((p, idx) => (
                <div
                  key={idx}
                  className="p-2.5 rounded-lg bg-white/[0.02] border border-white/[0.04] flex items-center justify-between"
                >
                  <div>
                    <span className="text-slate-200 font-medium">{p.prevalence}</span>
                    <span className="text-[10px] text-slate-400 block font-sans">
                      Recall maintained at {p.recall}%
                    </span>
                  </div>
                  <div className="text-right">
                    <span className={`font-bold ${p.precision > 80 ? 'text-emerald-400' : p.precision > 40 ? 'text-yellow-400' : 'text-red-400'}`}>
                      {p.precision}% True Precision
                    </span>
                    <span className="text-[10px] text-slate-400 block">
                      ~{p.falsePositives} false alarms / 10k
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Card 4: Threat Signature Coverage */}
          <div className="md:col-span-3 lg:col-span-2 glass-panel rounded-xl p-6 border border-white/[0.08] flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-mono text-indigo-400 uppercase tracking-wider flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4" />
                  <span>Targeted Banking Trojan Families</span>
                </span>
                <span className="text-[11px] font-mono text-slate-400">Heuristics + ML</span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-4">
                {[
                  { name: 'Hydra / Godfather', trait: 'Overlay injection & SMS 2FA interception', badge: 'Critical' },
                  { name: 'Hook / Ermac', trait: 'Accessibility VNC touch automation', badge: 'Critical' },
                  { name: 'SharkBot', trait: 'Direct Automated Transfer System (ATS) fraud', badge: 'Critical' },
                  { name: 'TeaBot / Anatsa', trait: 'Keylogger with live screen scraper', badge: 'Critical' },
                ].map((family, i) => (
                  <div key={i} className="p-3 rounded-lg bg-white/[0.02] border border-white/[0.05]">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-white font-mono">{family.name}</span>
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-500/20 text-red-300 font-mono">
                        {family.badge}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1 font-sans leading-snug">
                      {family.trait}
                    </p>
                  </div>
                ))}
              </div>
            </div>

            <div className="mt-5 pt-3 border-t border-white/[0.05] flex items-center justify-between text-xs text-slate-400">
              <span className="font-mono text-[11px]">Static signature evasion resistance: HIGH</span>
              <span className="text-sky-400 font-mono text-[11px]">330 Vectors Evaluated</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};
