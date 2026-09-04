import React from 'react';
import { Layers, Binary, Bot, CheckCircle2, ChevronRight, ShieldAlert, Zap, FileCode2 } from 'lucide-react';

export const Timeline: React.FC = () => {
  const steps = [
    {
      num: '01',
      title: 'Automated Decompilation',
      subtitle: 'Static Extraction Engine',
      icon: FileCode2,
      tag: 'APKTool + JADX',
      description:
        'Unpacks AndroidManifest.xml, binary XML resources, and Dalvik DEX executables into smali representations in seconds.',
      details: [
        'Decodes binary XML schemas & intent filters',
        'Extracts dangerous permission vectors (SMS, Overlay)',
        'Scans for hardcoded C2 URLs and direct IP endpoints',
        'Evaluates code entropy & ProGuard packer flags'
      ],
      accentColor: 'border-sky-500/30 text-sky-400 bg-sky-500/10'
    },
    {
      num: '02',
      title: 'XGBoost Feature Inference',
      subtitle: 'Trained on Drebin Permission Matrix',
      icon: Binary,
      tag: 'ROC-AUC 0.971',
      description:
        'Translates decompiled artifacts into a 330-dimensional feature space, balancing precision and recall at an operating threshold of 0.80.',
      details: [
        '330-feature permission & API call vectorization',
        'Calculates SHAP feature contribution ranking',
        'Prevents base-rate false alarm floods in enterprise streams',
        'Generates deterministic 0-100 fraud probability score'
      ],
      accentColor: 'border-emerald-500/30 text-emerald-400 bg-emerald-500/10'
    },
    {
      num: '03',
      title: 'Local GenAI Threat Briefing',
      subtitle: 'Llama 3.2 via Ollama',
      icon: Bot,
      tag: 'Zero Cloud Token Leak',
      description:
        'A local LLM synthesizes technical static signals into an executive CISO summary, risk taxonomy, and plain-English incident advice.',
      details: [
        'Maps findings to known Android banking families (Hydra, Hook)',
        'Delivers structured CISO action playbooks',
        'Produces plain-language briefings for branch compliance teams',
        'Runs fully on-premises without exfiltrating sample code'
      ],
      accentColor: 'border-indigo-500/30 text-indigo-400 bg-indigo-500/10'
    }
  ];

  return (
    <section id="pipeline-timeline-section" className="py-20 relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sky-500/10 border border-sky-500/20 text-sky-400 text-xs font-mono mb-4">
            <Zap className="w-3.5 h-3.5" />
            <span>TRI-STAGE THREAT PIPELINE</span>
          </div>
          <h2 className="text-2xl sm:text-3xl lg:text-4xl font-bold text-white tracking-tight font-sans">
            From Raw APK to Executive Threat Intel in Seconds
          </h2>
          <p className="mt-3 text-slate-400 text-sm sm:text-base leading-relaxed">
            Eliminate manual decompilation bottlenecks. APKGuard merges high-throughput machine learning
            with local generative explanations to protect financial perimeters.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 relative">
          {steps.map((step, idx) => {
            const Icon = step.icon;
            return (
              <div
                key={step.num}
                id={`timeline-step-${step.num}`}
                className="relative glass-panel rounded-xl p-6 border border-white/[0.08] hover:border-white/[0.18] transition-all flex flex-col justify-between group"
              >
                {/* Step Header */}
                <div>
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <div className={`w-10 h-10 rounded-lg flex items-center justify-center border ${step.accentColor}`}>
                        <Icon className="w-5 h-5" />
                      </div>
                      <div>
                        <span className="text-[11px] font-mono text-slate-400 block tracking-wider uppercase">
                          Phase {step.num}
                        </span>
                        <h3 className="text-base font-semibold text-white group-hover:text-sky-300 transition-colors">
                          {step.title}
                        </h3>
                      </div>
                    </div>
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-white/[0.04] border border-white/[0.08] text-slate-300">
                      {step.tag}
                    </span>
                  </div>

                  <p className="text-xs text-slate-400 leading-relaxed mb-5">
                    {step.description}
                  </p>

                  <div className="space-y-2 border-t border-white/[0.05] pt-4">
                    {step.details.map((item, itemIdx) => (
                      <div key={itemIdx} className="flex items-start gap-2 text-xs text-slate-300">
                        <CheckCircle2 className="w-3.5 h-3.5 text-sky-400/80 mt-0.5 shrink-0" />
                        <span className="leading-snug">{item}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="mt-6 pt-3 border-t border-white/[0.04] flex items-center justify-between text-[11px] font-mono text-slate-400">
                  <span>Latency: ~2.5 - 6.0s</span>
                  <span className="text-sky-400 flex items-center gap-1 group-hover:translate-x-1 transition-transform">
                    View Engine <ChevronRight className="w-3 h-3" />
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
};
