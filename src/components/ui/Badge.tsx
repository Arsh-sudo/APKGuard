import React from 'react';
import { VerdictCategory } from '../../types';

interface BadgeProps {
  category?: VerdictCategory | string;
  score?: number;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
  showIcon?: boolean;
}

export const Badge: React.FC<BadgeProps> = ({
  category = 'UNKNOWN',
  score,
  size = 'md',
  className = '',
  showIcon = true,
}) => {
  const norm = String(category || 'UNKNOWN').toUpperCase().replace(/[\s_-]+/g, '_');

  let bgClass = 'bg-slate-500/15 text-slate-300 border-slate-500/30';
  let dotClass = 'bg-slate-400';
  let label = 'UNASSESSED';

  if (norm.includes('CRITICAL')) {
    bgClass = 'bg-red-500/15 text-red-400 border-red-500/40 shadow-sm shadow-red-950/40';
    dotClass = 'bg-red-400 animate-pulse';
    label = 'CRITICAL THREAT';
  } else if (norm.includes('HIGH')) {
    bgClass = 'bg-amber-500/15 text-amber-400 border-amber-500/40';
    dotClass = 'bg-amber-400';
    label = 'HIGH RISK';
  } else if (norm.includes('SUSPICIOUS') || norm.includes('MEDIUM')) {
    bgClass = 'bg-yellow-500/15 text-yellow-300 border-yellow-500/40';
    dotClass = 'bg-yellow-300';
    label = 'SUSPICIOUS';
  } else if (norm.includes('LOW') || norm.includes('SAFE') || norm.includes('BENIGN')) {
    bgClass = 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';
    dotClass = 'bg-emerald-400';
    label = 'LOW RISK';
  } else {
    bgClass = 'bg-slate-500/15 text-slate-300 border-slate-500/30';
    dotClass = 'bg-slate-400';
    label = norm.length > 0 && norm !== 'UNKNOWN' ? norm.replace(/_/g, ' ') : 'UNKNOWN';
  }

  const sizeStyles = {
    sm: 'text-[10px] px-2 py-0.5 gap-1.5 font-mono',
    md: 'text-xs px-2.5 py-1 gap-1.5 font-mono',
    lg: 'text-sm px-3.5 py-1.5 gap-2 font-mono font-medium',
  };

  return (
    <span
      id={`badge-${norm.toLowerCase()}`}
      className={`inline-flex items-center rounded-md border font-medium tracking-wide transition-all ${sizeStyles[size]} ${bgClass} ${className}`}
    >
      {showIcon && <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dotClass}`} />}
      <span>{label}</span>
      {score !== undefined && (
        <span className="opacity-75 font-semibold">({score})</span>
      )}
    </span>
  );
};
