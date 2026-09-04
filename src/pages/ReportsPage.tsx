import React, { useEffect } from 'react';
import { useAppStore } from '../lib/store';
import { apiService } from '../lib/api';
import { ScanHistoryTable } from '../components/dashboard/ScanHistoryTable';
import { FileText, ShieldAlert, Download, ArrowLeft } from 'lucide-react';
import { Link } from 'react-router-dom';

export const ReportsPage: React.FC = () => {
  const { reports, setReports, addToast } = useAppStore();

  useEffect(() => {
    apiService.getReports().then((data) => setReports(data));
  }, [setReports]);

  const handleBulkExport = () => {
    const blob = new Blob([JSON.stringify(reports, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `apkguard_threat_intel_dump_${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
    addToast({
      type: 'success',
      title: 'Bulk Export Generated',
      message: `Exported ${reports.length} threat dossiers.`
    });
  };

  return (
    <div id="reports-archive-view" className="min-h-screen py-8 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-white/[0.06]">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400 mb-1">
            <Link to="/dashboard" className="hover:text-slate-200">DASHBOARD</Link>
            <span>/</span>
            <span className="text-sky-400">ARCHIVE</span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold font-mono text-white tracking-tight flex items-center gap-2">
            <FileText className="w-5 h-5 text-sky-400" />
            <span>Banking Specimen Threat Archive</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-sans">
            Comprehensive registry of static analysis evaluations, dangerous vectors, and CISO intelligence.
          </p>
        </div>

        <button
          id="bulk-export-btn"
          onClick={handleBulkExport}
          className="self-start sm:self-auto flex items-center gap-2 px-3.5 py-2 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.1] text-xs font-mono text-slate-200 hover:text-white transition-all"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Export All Telemetry (JSON)</span>
        </button>
      </div>

      {/* Main Table */}
      <ScanHistoryTable reports={reports} />
    </div>
  );
};
