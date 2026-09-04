import React from 'react';

interface RiskGaugeProps {
  score: number;
  category: string;
  confidence?: number;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({ score, category, confidence = 0.94 }) => {
  const radius = 65;
  const strokeWidth = 10;
  const circumference = 2 * Math.PI * radius;
  const progress = Math.min(Math.max(score, 0), 100);
  const strokeDashoffset = circumference - (progress / 100) * circumference;

  let color = '#1dd1a1'; // low
  let glowColor = 'rgba(29, 209, 161, 0.3)';

  if (score >= 70) {
    color = '#ff4d4d'; // critical
    glowColor = 'rgba(255, 77, 77, 0.4)';
  } else if (score >= 50) {
    color = '#ff9f43'; // high
    glowColor = 'rgba(255, 159, 67, 0.35)';
  } else if (score >= 30) {
    color = '#feca57'; // suspicious
    glowColor = 'rgba(254, 202, 87, 0.35)';
  }

  return (
    <div id="risk-gauge-container" className="flex flex-col items-center justify-center p-4">
      <div className="relative w-44 h-44 flex items-center justify-center">
        <svg className="w-full h-full transform -rotate-90" viewBox="0 0 160 160">
          {/* Background track */}
          <circle
            cx="80"
            cy="80"
            r={radius}
            fill="transparent"
            stroke="rgba(255, 255, 255, 0.06)"
            strokeWidth={strokeWidth}
          />
          {/* Progress circle */}
          <circle
            cx="80"
            cy="80"
            r={radius}
            fill="transparent"
            stroke={color}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
            style={{
              filter: `drop-shadow(0 0 8px ${glowColor})`,
            }}
          />
        </svg>

        {/* Center score readout */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className="text-4xl font-mono font-extrabold text-white tracking-tight">
            {score.toFixed(0)}
          </span>
          <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">
            out of 100
          </span>
          <span
            className="text-[11px] font-mono font-bold mt-1 px-2 py-0.5 rounded"
            style={{ color, backgroundColor: `${color}18` }}
          >
            {category}
          </span>
        </div>
      </div>

      <div className="mt-2 text-center text-xs font-mono text-slate-400">
        <div>XGBoost Calibration: <strong className="text-slate-200">τ = 0.80</strong></div>
        <div className="text-[11px] text-slate-400 mt-0.5">
          Confidence: {(confidence * 100).toFixed(1)}%
        </div>
      </div>
    </div>
  );
};
