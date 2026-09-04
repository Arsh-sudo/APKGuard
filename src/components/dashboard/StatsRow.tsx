import React from 'react';
import { SystemStats } from '../../types';
import { ShieldAlert, AlertTriangle, AlertCircle, CheckCircle, BarChart, FileSearch } from 'lucide-react';

interface StatsRowProps {
  stats: SystemStats;
}

export const StatsRow: React.FC<StatsRowProps> = ({ stats }) => {
  const cards = [
    {
      id: 'stat-total',
      label: 'Total Scanned',
      value: stats.total,
      subtext: 'Historical corpus',
      icon: FileSearch,
      color: 'text-sky-400',
      border: 'border-sky-500/20',
      bg: 'bg-sky-500/5',
    },
    {
      id: 'stat-critical',
      label: 'Critical Threats',
      value: stats.critical,
      subtext: 'Banking trojans & RATs',
      icon: ShieldAlert,
      color: 'text-red-400',
      border: 'border-red-500/30',
      bg: 'bg-red-500/10',
      glow: 'shadow-sm shadow-red-950/60',
    },
    {
      id: 'stat-high',
      label: 'High Risk',
      value: stats.high_risk,
      subtext: 'Credential phishers',
      icon: AlertTriangle,
      color: 'text-amber-400',
      border: 'border-amber-500/20',
      bg: 'bg-amber-500/5',
    },
    {
      id: 'stat-suspicious',
      label: 'Suspicious',
      value: stats.suspicious,
      subtext: 'Abusive permission sets',
      icon: AlertCircle,
      color: 'text-yellow-400',
      border: 'border-yellow-500/20',
      bg: 'bg-yellow-500/5',
    },
    {
      id: 'stat-low',
      label: 'Low Risk / Benign',
      value: stats.low_risk,
      subtext: 'Verified safe packages',
      icon: CheckCircle,
      color: 'text-emerald-400',
      border: 'border-emerald-500/20',
      bg: 'bg-emerald-500/5',
    },
    {
      id: 'stat-avg-score',
      label: 'Average Score',
      value: `${stats.avg_score}/100`,
      subtext: 'Fleet risk index',
      icon: BarChart,
      color: 'text-indigo-400',
      border: 'border-indigo-500/20',
      bg: 'bg-indigo-500/5',
    },
  ];

  return (
    <div id="stats-kpi-row" className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
      {cards.map((card) => {
        const Icon = card.icon;
        return (
          <div
            key={card.id}
            id={card.id}
            className={`glass-panel rounded-xl p-4 border ${card.border} ${card.bg} ${card.glow || ''} transition-all duration-200 hover:-translate-y-0.5`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-[11px] font-sans font-medium text-slate-400 uppercase tracking-wider">
                {card.label}
              </span>
              <Icon className={`w-4 h-4 ${card.color} opacity-90`} />
            </div>
            <div className={`text-2xl font-mono font-bold tracking-tight ${card.color}`}>
              {card.value}
            </div>
            <div className="text-[10px] text-slate-400 font-mono mt-1 truncate">
              {card.subtext}
            </div>
          </div>
        );
      })}
    </div>
  );
};
