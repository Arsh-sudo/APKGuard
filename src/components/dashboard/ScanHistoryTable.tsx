import React from 'react';
import { useNavigate } from 'react-router-dom';
import { APKReport, VerdictCategory } from '../../types';
import { Badge } from '../ui/Badge';
import { useAppStore } from '../../lib/store';
import { apiService } from '../../lib/api';
import { Search, Trash2, ArrowUpRight, ShieldAlert, Sparkles, Filter, FileText } from 'lucide-react';

interface ScanHistoryTableProps {
  reports: APKReport[];
}

export const ScanHistoryTable: React.FC<ScanHistoryTableProps> = ({ reports }) => {
  const navigate = useNavigate();
  const { searchTerm, setSearchTerm, selectedCategory, setSelectedCategory, deleteReport, addToast } = useAppStore();

  const categories: { label: string; value: VerdictCategory | 'ALL' }[] = [
    { label: 'All Packages', value: 'ALL' },
    { label: 'Critical', value: 'CRITICAL' },
    { label: 'High Risk', value: 'HIGH_RISK' },
    { label: 'Suspicious', value: 'SUSPICIOUS' },
    { label: 'Low Risk', value: 'LOW_RISK' },
  ];

  const filteredReports = reports.filter((r) => {
    const term = searchTerm.toLowerCase();
    const matchesSearch =
      r.apk_name.toLowerCase().includes(term) ||
      (r.manifest?.package || '').toLowerCase().includes(term) ||
      (r.static_analysis?.sha256 || '').toLowerCase().includes(term);

    if (!matchesSearch) return false;

    if (selectedCategory === 'ALL') return true;
    const cat = String(r.ml_scoring?.category || '').toUpperCase().replace(/\s+/g, '_');
    return cat.includes(selectedCategory);
  });

  const handleDelete = async (e: React.MouseEvent, apkName: string) => {
    e.stopPropagation();
    try {
      await apiService.deleteReport(apkName);
      deleteReport(apkName);
      addToast({
        type: 'info',
        title: 'Report Removed',
        message: `Deleted static scan profile for ${apkName}`
      });
    } catch {
      deleteReport(apkName);
    }
  };

  return (
    <div id="scan-history-panel" className="glass-panel rounded-2xl border border-white/[0.08] overflow-hidden">
      {/* Table Header & Controls */}
      <div className="p-5 border-b border-white/[0.06] flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-white font-sans flex items-center gap-2">
            <span>Threat Intelligence Archive</span>
            <span className="text-xs font-mono text-slate-400 font-normal">
              ({filteredReports.length} recorded)
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Historical static evaluations, risk probabilities, and LLM threat classifications.
          </p>
        </div>

        {/* Search input and category filter */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 w-full md:w-auto">
          {/* Search */}
          <div className="relative flex-1 sm:w-64">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              id="report-search-input"
              type="text"
              placeholder="Search package or hash..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-white/[0.03] border border-white/[0.08] text-xs font-mono text-white placeholder:text-slate-400 focus:outline-none focus:border-sky-500/50"
            />
          </div>

          {/* Category Tabs */}
          <div className="flex items-center gap-1 overflow-x-auto pb-1 sm:pb-0">
            {categories.map((cat) => {
              const active = selectedCategory === cat.value;
              return (
                <button
                  key={cat.value}
                  id={`filter-tab-${cat.value.toLowerCase()}`}
                  onClick={() => setSelectedCategory(cat.value)}
                  className={`px-2.5 py-1 rounded-md text-[11px] font-mono whitespace-nowrap transition-colors border ${
                    active
                      ? 'bg-sky-500/20 text-sky-300 border-sky-500/40'
                      : 'bg-white/[0.02] text-slate-400 border-white/[0.04] hover:text-slate-200'
                  }`}
                >
                  {cat.label}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Table listing */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-white/[0.04] bg-white/[0.01] text-[11px] font-mono text-slate-400 uppercase tracking-wider">
              <th className="py-3 px-5">Specimen / Package</th>
              <th className="py-3 px-4">Scanned</th>
              <th className="py-3 px-4">Danger Perms</th>
              <th className="py-3 px-4">XGBoost Score</th>
              <th className="py-3 px-4">Verdict</th>
              <th className="py-3 px-5 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.03] text-xs">
            {filteredReports.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-12 text-center text-slate-400 font-mono">
                  No APK threat records matched your filter query.
                </td>
              </tr>
            ) : (
              filteredReports.map((report) => {
                const score = report.ml_scoring?.final_score ?? 0;
                const dangerousCount = report.manifest?.dangerous_permissions?.length ?? 0;
                const hasLLM = !!report.llm_analysis;

                return (
                  <tr
                    key={report.apk_name}
                    id={`report-row-${report.apk_name.replace(/[^a-zA-Z0-9]/g, '-')}`}
                    onClick={() => navigate(`/report/${report.apk_name}`)}
                    className="hover:bg-white/[0.025] cursor-pointer transition-colors group"
                  >
                    {/* Specimen / Package */}
                    <td className="py-3.5 px-5">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded bg-white/[0.03] border border-white/[0.06] flex items-center justify-center shrink-0 text-slate-400 group-hover:text-sky-400 group-hover:border-sky-500/30 transition-colors">
                          <FileText className="w-4 h-4" />
                        </div>
                        <div className="min-w-0">
                          <div className="font-mono font-semibold text-slate-200 group-hover:text-white truncate max-w-xs">
                            {report.apk_name}
                          </div>
                          <div className="font-mono text-[10px] text-slate-400 truncate max-w-xs">
                            {report.manifest?.package || 'Unknown package'}
                          </div>
                        </div>
                      </div>
                    </td>

                    {/* Scanned time */}
                    <td className="py-3.5 px-4 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                      {new Date(report.analysed_at).toLocaleDateString()} • {new Date(report.analysed_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </td>

                    {/* Dangerous Perms */}
                    <td className="py-3.5 px-4 font-mono whitespace-nowrap">
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] ${
                        dangerousCount >= 5
                          ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                          : dangerousCount > 0
                          ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                          : 'bg-white/[0.03] text-slate-400 border border-white/[0.05]'
                      }`}>
                        {dangerousCount} dangerous
                      </span>
                    </td>

                    {/* XGBoost score bar */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 rounded-full bg-white/[0.06] overflow-hidden">
                          <div
                            className={`h-full ${
                              score >= 70
                                ? 'bg-red-500'
                                : score >= 50
                                ? 'bg-amber-500'
                                : score >= 30
                                ? 'bg-yellow-400'
                                : 'bg-emerald-400'
                            }`}
                            style={{ width: `${score}%` }}
                          />
                        </div>
                        <span className="font-mono text-xs font-bold text-slate-200">
                          {score.toFixed(1)}
                        </span>
                      </div>
                    </td>

                    {/* Verdict Badge */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <Badge category={report.ml_scoring?.category} size="sm" />
                        {hasLLM && (
                          <span title="LLM CISO briefing available">
                            <Sparkles className="w-3 h-3 text-sky-400" />
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Actions */}
                    <td className="py-3.5 px-5 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          id={`view-btn-${report.apk_name}`}
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/report/${report.apk_name}`);
                          }}
                          className="px-2.5 py-1 rounded bg-white/[0.04] hover:bg-white/[0.08] text-slate-300 hover:text-white font-mono text-[11px] flex items-center gap-1 transition-colors border border-white/[0.06]"
                        >
                          <span>Review</span>
                          <ArrowUpRight className="w-3 h-3" />
                        </button>
                        <button
                          id={`delete-btn-${report.apk_name}`}
                          onClick={(e) => handleDelete(e, report.apk_name)}
                          className="p-1 text-slate-400 hover:text-red-400 transition-colors"
                          title="Delete report"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
