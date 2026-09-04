import React from 'react';
import { Cpu, Terminal, Shield, Code2, Database, Layers } from 'lucide-react';

export const TechStack: React.FC = () => {
  const stack = [
    {
      name: 'XGBoost v1.7.4',
      role: 'Classifier & SHAP Attribution',
      desc: 'Gradient-boosted decision trees trained on 330 Android permission & API features.',
      icon: Cpu,
      color: 'text-emerald-400',
    },
    {
      name: 'Llama 3.2 3B',
      role: 'Local LLM Explainer (Ollama)',
      desc: 'On-premises generative intelligence that synthesizes CISO playbooks without cloud API calls.',
      icon: Terminal,
      color: 'text-sky-400',
    },
    {
      name: 'APKTool & JADX',
      role: 'Static Bytecode Disassembly',
      desc: 'Extracts AndroidManifest.xml, intent filters, services, smali bytecode, and assets.',
      icon: Code2,
      color: 'text-indigo-400',
    },
    {
      name: 'Drebin Matrix',
      role: 'Malware Feature Corpus',
      desc: 'Validated benchmark dataset pairing malicious banking trojans against legitimate apps.',
      icon: Database,
      color: 'text-amber-400',
    },
    {
      name: 'FastAPI Spec & Node',
      role: 'High-Throughput Pipeline',
      desc: 'Async streaming pipeline supporting multi-worker task queuing and sub-second responses.',
      icon: Layers,
      color: 'text-cyan-400',
    },
    {
      name: 'Bank CISO Ready',
      role: 'Enterprise Design System',
      desc: 'High-density dark cybersecurity console inspired by Palantir and modern SOC terminals.',
      icon: Shield,
      color: 'text-red-400',
    },
  ];

  return (
    <section id="tech-stack-section" className="py-16 border-t border-white/[0.05]">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col md:flex-row md:items-end justify-between mb-10">
          <div>
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block mb-1">
              Engine Specifications
            </span>
            <h3 className="text-xl sm:text-2xl font-bold text-white tracking-tight font-sans">
              Built on Battle-Tested Malware Research Tools
            </h3>
          </div>
          <p className="text-xs text-slate-400 max-w-md mt-2 md:mt-0">
            Engineered for security analysts who require reproducible bytecode telemetry and verifiable ML indicators.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {stack.map((item, idx) => {
            const Icon = item.icon;
            return (
              <div
                key={idx}
                className="p-4 rounded-lg bg-white/[0.02] border border-white/[0.05] hover:border-white/[0.12] transition-colors"
              >
                <div className="flex items-center gap-3 mb-2">
                  <div className="w-8 h-8 rounded bg-white/[0.04] flex items-center justify-center border border-white/[0.06]">
                    <Icon className={`w-4 h-4 ${item.color}`} />
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold text-white font-mono">{item.name}</h4>
                    <span className="text-[10px] text-slate-400 block font-sans">{item.role}</span>
                  </div>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed font-sans">
                  {item.desc}
                </p>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
};
