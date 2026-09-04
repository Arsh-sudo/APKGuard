import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ParticleCanvas } from '../components/landing/ParticleCanvas';
import { Timeline } from '../components/landing/Timeline';
import { BentoGrid } from '../components/landing/BentoGrid';
import { TechStack } from '../components/landing/TechStack';
import { Shield, ArrowRight, Lock, Terminal, Cpu, CheckCircle2, ChevronRight, Activity } from 'lucide-react';

export const LandingPage: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-[#050508] relative selection:bg-sky-500/20 selection:text-white">
      {/* Hero Section */}
      <section id="hero-section" className="relative pt-24 pb-20 overflow-hidden border-b border-white/[0.05]">
        {/* Dynamic particle network canvas */}
        <ParticleCanvas />

        {/* Ambient radial glow */}
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[350px] bg-sky-500/10 rounded-full blur-[120px] pointer-events-none" />
        <div className="absolute top-1/3 left-1/3 w-[300px] h-[300px] bg-indigo-500/10 rounded-full blur-[100px] pointer-events-none" />

        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          {/* Tagline Badge */}
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-white/[0.03] border border-white/[0.08] text-xs font-mono text-slate-300 mb-8 backdrop-blur-md">
            <span className="w-2 h-2 rounded-full bg-sky-400 animate-pulse" />
            <span className="text-sky-400 font-semibold">Razorpay Buildathon</span>
            <span className="text-slate-600">|</span>
            <span>Zero-Token Cloud Leak Defense</span>
          </div>

          {/* Main Headline */}
          <h1 className="text-4xl sm:text-6xl lg:text-7xl font-bold tracking-tight text-white font-sans max-w-5xl mx-auto leading-[1.08]">
            Static Banking Threat Intel.
            <br />
            <span className="bg-gradient-to-r from-sky-400 via-indigo-300 to-emerald-400 bg-clip-text text-transparent">
              Powered by XGBoost & Local LLMs.
            </span>
          </h1>

          {/* Subtitle */}
          <p className="mt-6 text-base sm:text-lg text-slate-400 max-w-3xl mx-auto leading-relaxed font-sans">
            Disassemble Android binaries in seconds, score 330 bytecode feature vectors with XGBoost
            calibrated at optimal <strong className="text-slate-200">τ = 0.80</strong>, and generate structured CISO briefs via Llama 3.2 without sending proprietary code to the cloud.
          </p>

          {/* Call to action buttons */}
          <div className="mt-10 flex flex-col sm:flex-row items-center justify-center gap-4">
            <button
              id="hero-launch-console-btn"
              onClick={() => navigate('/dashboard')}
              className="w-full sm:w-auto flex items-center justify-center gap-2 px-8 py-3.5 rounded-xl bg-sky-500 hover:bg-sky-400 text-slate-950 font-mono font-bold text-sm uppercase tracking-wider transition-all shadow-xl shadow-sky-500/20 hover:scale-[1.02]"
            >
              <Shield className="w-4 h-4" />
              <span>Launch Threat Console</span>
              <ArrowRight className="w-4 h-4 ml-1" />
            </button>

            <button
              id="hero-explore-reports-btn"
              onClick={() => navigate('/reports')}
              className="w-full sm:w-auto flex items-center justify-center gap-2 px-7 py-3.5 rounded-xl bg-white/[0.04] hover:bg-white/[0.08] text-white border border-white/[0.12] font-mono text-sm transition-all"
            >
              <span>Explore Specimen Archive</span>
              <ChevronRight className="w-4 h-4 text-slate-400" />
            </button>
          </div>

          {/* Security & Metric strip */}
          <div className="mt-16 grid grid-cols-2 md:grid-cols-4 gap-4 max-w-4xl mx-auto pt-8 border-t border-white/[0.05] text-left">
            <div className="p-3 rounded-lg bg-white/[0.01] border border-white/[0.03]">
              <div className="text-xl font-mono font-bold text-emerald-400">0.971 ROC-AUC</div>
              <div className="text-xs text-slate-400 font-sans mt-0.5">XGBoost Drebin benchmark</div>
            </div>
            <div className="p-3 rounded-lg bg-white/[0.01] border border-white/[0.03]">
              <div className="text-xl font-mono font-bold text-sky-400">1.4% False Positives</div>
              <div className="text-xs text-slate-400 font-sans mt-0.5">At calibrated 0.80 threshold</div>
            </div>
            <div className="p-3 rounded-lg bg-white/[0.01] border border-white/[0.03]">
              <div className="text-xl font-mono font-bold text-indigo-400">On-Premises LLM</div>
              <div className="text-xs text-slate-400 font-sans mt-0.5">Llama 3.2 via Ollama</div>
            </div>
            <div className="p-3 rounded-lg bg-white/[0.01] border border-white/[0.03]">
              <div className="text-xl font-mono font-bold text-white">100% Static</div>
              <div className="text-xs text-slate-400 font-sans mt-0.5">Zero runtime sandbox risks</div>
            </div>
          </div>
        </div>
      </section>

      {/* Tri-stage Pipeline Timeline */}
      <Timeline />

      {/* Empirical Benchmarks, Threshold Sweeper & Bento Grid */}
      <BentoGrid />

      {/* Technology Stack Specifications */}
      <TechStack />
    </div>
  );
};
