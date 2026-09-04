import React, { useState, useEffect } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { Shield, Sparkles, Activity, FileText, Cpu, LayoutDashboard, Upload, Menu, X } from 'lucide-react';
import { useAppStore } from '../../lib/store';
import { apiService } from '../../lib/api';

export const Navbar: React.FC = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { useLLM, setUseLLM, apiOnline, ollamaOnline, setSystemHealth, addToast } = useAppStore();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    // Initial health check
    apiService.checkHealth().then(({ api, ollama }) => {
      setSystemHealth(api, ollama);
    });

    const interval = setInterval(() => {
      apiService.checkHealth().then(({ api, ollama }) => {
        setSystemHealth(api, ollama);
      });
    }, 20000);

    return () => clearInterval(interval);
  }, [setSystemHealth]);

  const navLinks = [
    { label: 'Overview', path: '/', icon: Activity },
    { label: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
    { label: 'Threat Reports', path: '/reports', icon: FileText },
  ];

  return (
    <header id="main-header" className="sticky top-0 z-40 w-full border-b border-white/[0.06] bg-[#050508]/85 backdrop-blur-xl">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand */}
        <div className="flex items-center gap-6">
          <Link
            id="brand-logo"
            to="/"
            className="flex items-center gap-2.5 text-white font-mono tracking-wider group"
          >
            <div className="w-9 h-9 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400 group-hover:border-sky-400/60 group-hover:bg-sky-500/20 transition-all shadow-sm shadow-sky-950">
              <Shield className="w-5 h-5 stroke-[2.2]" />
            </div>
            <div className="flex flex-col">
              <span className="font-bold text-base tracking-tight text-white flex items-center gap-1.5">
                APKGuard
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-sky-500/20 text-sky-300 font-mono font-medium border border-sky-500/30">
                  CISO v2
                </span>
              </span>
              <span className="text-[10px] text-slate-400 font-sans tracking-tight">
                Banking Threat Analysis
              </span>
            </div>
          </Link>

          {/* Desktop Nav links */}
          <nav className="hidden md:flex items-center gap-1 pl-4 border-l border-white/[0.08]">
            {navLinks.map((item) => {
              const isActive = location.pathname === item.path;
              const Icon = item.icon;
              return (
                <Link
                  key={item.path}
                  id={`nav-link-${item.label.toLowerCase().replace(/\s+/g, '-')}`}
                  to={item.path}
                  className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                    isActive
                      ? 'bg-white/[0.08] text-white border border-white/[0.08]'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-white/[0.03]'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5 opacity-80" />
                  <span>{item.label}</span>
                </Link>
              );
            })}
          </nav>
        </div>

        {/* System telemetry & Controls */}
        <div className="hidden lg:flex items-center gap-4">
          {/* Health Indicators */}
          <div className="flex items-center gap-2 px-2.5 py-1 rounded-full bg-white/[0.02] border border-white/[0.05] text-[11px] font-mono">
            <span className="flex items-center gap-1.5">
              <span className={`w-1.5 h-1.5 rounded-full ${apiOnline ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`} />
              <span className="text-slate-300">{apiOnline ? 'API LIVE' : 'API DISCONNECTED'}</span>
            </span>
            <span className="text-slate-700">|</span>
            <span className="flex items-center gap-1.5">
              <Cpu className="w-3 h-3 text-sky-400" />
              <span className="text-slate-300">{ollamaOnline ? 'LLM READY' : 'LLM FALLBACK'}</span>
            </span>
          </div>

          {/* AI Mode Toggle */}
          <div className="flex items-center gap-2 px-3 py-1 rounded-lg bg-white/[0.03] border border-white/[0.06]">
            <Sparkles className={`w-3.5 h-3.5 ${useLLM ? 'text-sky-400' : 'text-slate-500'}`} />
            <span className="text-xs font-mono text-slate-300">AI Explainer</span>
            <button
              id="ai-mode-toggle"
              type="button"
              onClick={() => {
                const next = !useLLM;
                setUseLLM(next);
                addToast({
                  type: 'info',
                  title: next ? 'AI Threat Intelligence Enabled' : 'Quick Scoring Mode Active',
                  message: next
                    ? 'Synthesizes CISO briefs and executive explanations via Llama 3.2.'
                    : 'Bypasses GenAI synthesis for ultra-fast XGBoost-only throughput.'
                });
              }}
              className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                useLLM ? 'bg-sky-600' : 'bg-slate-800'
              }`}
              aria-label="Toggle AI analysis"
            >
              <span
                className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow-lg ring-0 transition duration-200 ease-in-out ${
                  useLLM ? 'translate-x-4' : 'translate-x-0'
                }`}
              />
            </button>
          </div>

          {/* Upload Quick CTA */}
          <button
            id="nav-quick-upload-btn"
            onClick={() => navigate('/dashboard')}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-sky-500/10 hover:bg-sky-500/20 text-sky-300 hover:text-white border border-sky-500/30 hover:border-sky-400/50 text-xs font-mono font-medium transition-all group"
          >
            <Upload className="w-3.5 h-3.5 transition-transform group-hover:-translate-y-0.5" />
            <span>Scan APK</span>
            <kbd className="hidden xl:inline text-[9px] px-1 py-0.5 bg-black/40 rounded border border-white/10 text-slate-400">
              ⌘U
            </kbd>
          </button>
        </div>

        {/* Mobile menu button */}
        <div className="flex md:hidden items-center gap-2">
          <button
            id="mobile-menu-btn"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-white/[0.05]"
            aria-label="Toggle menu"
          >
            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </div>

      {/* Mobile drawer */}
      {mobileMenuOpen && (
        <div id="mobile-nav-menu" className="md:hidden border-t border-white/[0.06] bg-[#07070c] px-4 pt-3 pb-5 space-y-3">
          <div className="flex flex-col gap-1">
            {navLinks.map((item) => {
              const isActive = location.pathname === item.path;
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  onClick={() => setMobileMenuOpen(false)}
                  className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium ${
                    isActive ? 'bg-white/[0.08] text-white' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <item.icon className="w-4 h-4" />
                  <span>{item.label}</span>
                </Link>
              );
            })}
          </div>
          <div className="pt-2 border-t border-white/[0.06] flex items-center justify-between px-2">
            <span className="text-xs font-mono text-slate-400">AI Threat Mode</span>
            <button
              onClick={() => setUseLLM(!useLLM)}
              className={`text-xs px-2.5 py-1 rounded font-mono ${useLLM ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30' : 'bg-slate-800 text-slate-400'}`}
            >
              {useLLM ? 'ENABLED' : 'DISABLED'}
            </button>
          </div>
        </div>
      )}
    </header>
  );
};
