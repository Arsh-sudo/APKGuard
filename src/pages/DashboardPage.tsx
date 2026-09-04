import React, { useEffect } from 'react';
import { useAppStore } from '../lib/store';
import { apiService } from '../lib/api';
import { StatsRow } from '../components/dashboard/StatsRow';
import { UploadZone } from '../components/dashboard/UploadZone';
import { ScanHistoryTable } from '../components/dashboard/ScanHistoryTable';
import { ActivityFeed } from '../components/dashboard/ActivityFeed';
import { LayoutDashboard, RefreshCw } from 'lucide-react';

export const DashboardPage: React.FC = () => {
  const { stats, reports, setStats, setReports } = useAppStore();

  const reloadData = () => {
    apiService.getStats().then((data) => setStats(data));
    apiService.getReports().then((data) => setReports(data));
  };

  useEffect(() => {
    reloadData();
    const interval = setInterval(reloadData, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div id="dashboard-view" className="min-h-screen py-8 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto space-y-6">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold font-mono text-white tracking-tight flex items-center gap-2">
            <LayoutDashboard className="w-5 h-5 text-sky-400" />
            <span>Threat Intelligence Operations Center</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-sans">
            Real-time Android APK decompilation, XGBoost scoring, and Llama 3.2 briefing pipeline.
          </p>
        </div>

        <button
          id="refresh-dashboard-btn"
          onClick={reloadData}
          className="self-start sm:self-auto flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white/[0.03] hover:bg-white/[0.06] border border-white/[0.08] text-xs font-mono text-slate-300 hover:text-white transition-all"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Sync State</span>
        </button>
      </div>

      {/* KPI Stats Row */}
      <StatsRow stats={stats} />

      {/* Upload Zone & Quick Samples */}
      <UploadZone />

      {/* Grid: Scan History & Live Terminal Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <ScanHistoryTable reports={reports} />
        </div>
        <div className="lg:col-span-1">
          <ActivityFeed />
        </div>
      </div>
    </div>
  );
};
