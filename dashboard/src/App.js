/* eslint-disable */
import { useState, useEffect, useCallback } from "react";
import axios from "axios";
import { Shield, Upload, AlertTriangle, CheckCircle, Clock, BarChart2, FileText, ChevronRight, Trash2, Zap, Brain, Wifi, WifiOff } from "lucide-react";
import { RadialBarChart, RadialBar, PolarAngleAxis, ResponsiveContainer } from "recharts";
import "./App.css";

const API = process.env.REACT_APP_API_URL || "http://localhost:8000";

// ── Score colour helper ───────────────────────────────────────────
function scoreColor(score) {
  if (score >= 70) return "#ff2d55";
  if (score >= 50) return "#ff9f0a";
  if (score >= 30) return "#ffd60a";
  return "#30d158";
}

function categoryIcon(cat) {
  if (!cat) return <Clock size={14} />;
  if (cat.includes("CRITICAL")) return <AlertTriangle size={14} />;
  if (cat.includes("HIGH"))     return <AlertTriangle size={14} />;
  if (cat.includes("SUSPICIOUS")) return <Clock size={14} />;
  return <CheckCircle size={14} />;
}

// ── Risk gauge ────────────────────────────────────────────────────
function RiskGauge({ score, category }) {
  const color = scoreColor(score);
  const data  = [{ value: score, fill: color }];
  return (
    <div className="gauge-wrap">
      <ResponsiveContainer width="100%" height={180}>
        <RadialBarChart
          cx="50%" cy="80%" innerRadius="70%" outerRadius="100%"
          startAngle={180} endAngle={0} data={data}
        >
          <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
          <RadialBar background={{ fill: "#1c1c1e" }} dataKey="value" cornerRadius={8} />
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="gauge-label" style={{ color }}>
        <span className="gauge-score">{score}</span>
        <span className="gauge-max">/100</span>
      </div>
      <div className="gauge-category" style={{ color }}>{category || "—"}</div>
    </div>
  );
}

// ── Progress bar ──────────────────────────────────────────────────
function ProgressBar({ progress, message }) {
  return (
    <div className="progress-wrap">
      <div className="progress-header">
        <span className="progress-msg">{message}</span>
        <span className="progress-pct">{progress}%</span>
      </div>
      <div className="progress-track">
        <div className="progress-fill" style={{ width: `${progress}%` }} />
      </div>
    </div>
  );
}

// ── API Status Banner ─────────────────────────────────────────────
function APIBanner({ online }) {
  if (online) return null;
  return (
    <div className="api-banner">
      <WifiOff size={14}/>
      <span>
        <b>Demo Mode</b> — API offline. To run locally: clone the repo, run
        <code> docker-compose up</code>, then visit <code>localhost:3000</code>
      </span>
      <a href="https://github.com/Arsh-sudo/APKGuard" target="_blank" rel="noreferrer" className="banner-link">
        GitHub →
      </a>
    </div>
  );
}

// ── Demo data shown when API is offline ──────────────────────────
const DEMO_REPORTS = [
  {
    apk_name: "BankingTrojan.apk",
    package: "krep.itmtd.ywtjexf",
    final_score: 99.9,
    category: "CRITICAL THREAT",
    analysed_at: "2026-05-20T23:46:56",
    has_llm: false,
  },
  {
    apk_name: "Calculator.apk",
    package: "com.google.android.calculator",
    final_score: 27.5,
    category: "LOW RISK",
    analysed_at: "2026-05-20T22:19:42",
    has_llm: true,
  },
];

const DEMO_STATS = {
  total: 2, critical: 1, high_risk: 0,
  suspicious: 0, low_risk: 1, avg_score: 63.7, with_llm: 1,
};

const DEMO_DETAIL_CALC = {
  apk_name: "Calculator.apk",
  apk_size_kb: 6571.1,
  analysed_at: "2026-05-20T22:19:42",
  manifest: {
    package: "com.google.android.calculator",
    version_name: "8.1",
    activities_count: 2,
    services_count: 0,
    receivers_count: 1,
    dangerous_permissions: [],
    permissions: ["android.permission.INTERNET","android.permission.WAKE_LOCK"],
  },
  static_analysis: {
    total_java_files: 3538,
    obfuscation_flag: false,
    suspicious_keywords: { Base64: 8, DES: 19, overlay: 4, getRuntime: 4 },
    hardcoded_urls: [],
    hardcoded_ips: [],
  },
  heuristic_scoring: {
    heuristic_score: 67,
    category: "HIGH RISK",
    reasons: [
      "Suspicious code: Base64 found in 8 file(s) (+3)",
      "Suspicious code: DES found in 19 file(s) (+3)",
      "Suspicious code: getRuntime found in 4 file(s) (+10)",
    ],
  },
  ml_scoring: { ml_score: 1.1, final_score: 27.5, category: "LOW RISK" },
  llm_analysis: {
    model: "llama3.2",
    threat_summary: "VERDICT: This app is SAFE — Google Calculator.\nTHREAT TYPE: Legitimate App\nKEY RISKS:\n• Base64/DES in standard libraries only\n• No dangerous permissions\n• ML correctly identifies as benign\nRECOMMENDED ACTION: Safe to allow",
    permission_analysis: "No dangerous permissions declared — very low risk.",
    code_analysis: "Base64 and DES keywords appear in standard Android libraries. No malicious intent detected.",
    plain_explanation: "This is Google Calculator. Score 27.5/100 confirms it is safe.",
  },
};

const DEMO_DETAIL = {
  apk_name: "BankingTrojan.apk",
  apk_size_kb: 312.4,
  analysed_at: "2026-05-20T23:46:56",
  manifest: {
    package: "krep.itmtd.ywtjexf",
    version_name: "1.0",
    activities_count: 3,
    services_count: 2,
    receivers_count: 4,
    dangerous_permissions: [
      "READ_SMS","SEND_SMS","RECEIVE_SMS",
      "READ_CONTACTS","READ_CALL_LOG",
      "READ_PHONE_STATE","SYSTEM_ALERT_WINDOW",
      "RECEIVE_BOOT_COMPLETED",
    ],
    permissions: [
      "android.permission.READ_SMS","android.permission.SEND_SMS",
      "android.permission.RECEIVE_SMS","android.permission.READ_CONTACTS",
      "android.permission.READ_CALL_LOG","android.permission.INTERNET",
      "android.permission.READ_PHONE_STATE","android.permission.SYSTEM_ALERT_WINDOW",
      "android.permission.RECEIVE_BOOT_COMPLETED","android.permission.WAKE_LOCK",
    ],
  },
  static_analysis: {
    total_java_files: 335,
    obfuscation_flag: false,
    suspicious_keywords: {
      AccessibilityService: 2, DevicePolicyManager: 1,
      sendTextMessage: 3, getDeviceId: 2,
      overlay: 4, addJavascriptInterface: 1,
      HttpURLConnection: 5, WebView: 2,
    },
    hardcoded_urls: ["http://185.234.xx.xx/gate.php","http://update.malicious-c2.ru/cmd"],
    hardcoded_ips: ["185.234.xx.xx","91.108.xx.xx"],
  },
  heuristic_scoring: {
    heuristic_score: 100,
    category: "CRITICAL THREAT",
    reasons: [
      "Dangerous permission: READ_SMS (+15)",
      "Dangerous permission: SEND_SMS (+15)",
      "Suspicious code: AccessibilityService found in 2 file(s) (+15)",
      "Suspicious code: overlay found in 4 file(s) (+3)",
      "Dangerous permission: SYSTEM_ALERT_WINDOW (+18)",
    ],
  },
  ml_scoring: {
    ml_score: 99.8,
    final_score: 99.9,
    category: "CRITICAL THREAT",
  },
  llm_analysis: null,
};

// ── Upload zone ───────────────────────────────────────────────────
function UploadZone({ onUpload, loading, apiOnline }) {
  const [dragging, setDragging] = useState(false);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file?.name.endsWith(".apk")) onUpload(file);
  }, [onUpload]);

  const handleChange = (e) => {
    const file = e.target.files[0];
    if (file) onUpload(file);
  };

  return (
    <div
      className={`upload-zone ${dragging ? "drag-over" : ""} ${loading ? "loading" : ""} ${!apiOnline ? "offline" : ""}`}
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
      onClick={() => apiOnline && !loading && document.getElementById("apk-input").click()}
    >
      <input id="apk-input" type="file" accept=".apk" onChange={handleChange} hidden />
      <div className="upload-icon">
        {apiOnline ? <Upload size={32} /> : <WifiOff size={32} color="#636366"/>}
      </div>
      <div className="upload-title">
        {loading ? "Analysing..." : apiOnline ? "Drop APK here" : "API Offline"}
      </div>
      <div className="upload-sub">
        {loading
          ? "Pipeline running — results appear below"
          : apiOnline
          ? "or click to browse · .apk files only · max 100MB"
          : "Run docker-compose up locally to enable live scanning"}
      </div>
    </div>
  );
}

// ── Report detail panel ───────────────────────────────────────────
function ReportPanel({ report, onClose }) {
  const [tab, setTab] = useState("summary");
  if (!report) return null;

  const ml   = report.ml_scoring || {};
  const h    = report.heuristic_scoring || {};
  const man  = report.manifest || {};
  const stat = report.static_analysis || {};
  const llm  = report.llm_analysis || null;
  const score    = ml.final_score ?? h.heuristic_score ?? 0;
  const category = ml.category   ?? h.category ?? "UNKNOWN";
  const color    = scoreColor(score);

  const tabs = [
    { id: "summary",     label: "Summary",     icon: <BarChart2 size={13}/> },
    { id: "permissions", label: "Permissions",  icon: <Shield size={13}/> },
    { id: "code",        label: "Code Signals", icon: <FileText size={13}/> },
    { id: "llm",         label: "AI Analysis",  icon: <Brain size={13}/> },
  ];

  return (
    <div className="panel-overlay" onClick={onClose}>
      <div className="panel" onClick={e => e.stopPropagation()}>
        <div className="panel-header" style={{ borderColor: color }}>
          <div>
            <div className="panel-apk">{report.apk_name}</div>
            <div className="panel-pkg">{man.package}</div>
          </div>
          <div className="panel-score" style={{ color }}>{score}<span>/100</span></div>
          <button className="panel-close" onClick={onClose}>✕</button>
        </div>
        <div className="panel-tabs">
          {tabs.map(t => (
            <button key={t.id} className={`panel-tab ${tab === t.id ? "active" : ""}`} onClick={() => setTab(t.id)}>
              {t.icon} {t.label}
            </button>
          ))}
        </div>
        <div className="panel-body">
          {tab === "summary" && (
            <div className="tab-summary">
              <RiskGauge score={score} category={category} />
              <div className="summary-grid">
                <div className="sum-item"><span>Package</span><b>{man.package}</b></div>
                <div className="sum-item"><span>Version</span><b>{man.version_name || "?"}</b></div>
                <div className="sum-item"><span>File Size</span><b>{report.apk_size_kb} KB</b></div>
                <div className="sum-item"><span>Java Files</span><b>{stat.total_java_files || 0}</b></div>
                <div className="sum-item"><span>Activities</span><b>{man.activities_count || 0}</b></div>
                <div className="sum-item"><span>Services</span><b>{man.services_count || 0}</b></div>
                <div className="sum-item"><span>Obfuscated</span><b>{stat.obfuscation_flag ? "⚠ Yes" : "✓ No"}</b></div>
                <div className="sum-item"><span>Native Libs</span><b>{stat.native_lib_count ?? 0}</b></div>
              </div>
              {h.reasons?.length > 0 && (
                <div className="reasons">
                  <div className="reasons-title">Risk Factors</div>
                  {h.reasons.map((r, i) => (
                    <div key={i} className="reason-row"><ChevronRight size={12} color="#ff9f0a" /> {r}</div>
                  ))}
                </div>
              )}
            </div>
          )}
          {tab === "permissions" && (
            <div className="tab-perms">
              {man.dangerous_permissions?.length > 0 ? (
                <>
                  <div className="perm-section-title danger">
                    <AlertTriangle size={13}/> Dangerous Permissions ({man.dangerous_permissions.length})
                  </div>
                  {man.dangerous_permissions.map((p, i) => (
                    <div key={i} className="perm-row danger">{p}</div>
                  ))}
                </>
              ) : (
                <div className="perm-empty"><CheckCircle size={20} color="#30d158"/> No dangerous permissions</div>
              )}
              {man.permissions?.length > 0 && (
                <>
                  <div className="perm-section-title" style={{marginTop:"1.2rem"}}>All Permissions ({man.permissions.length})</div>
                  <div className="perm-all">
                    {man.permissions.map((p, i) => (
                      <div key={i} className="perm-chip">{p.split(".").pop()}</div>
                    ))}
                  </div>
                </>
              )}
            </div>
          )}
          {tab === "code" && (
            <div className="tab-code">
              {Object.keys(stat.suspicious_keywords || {}).length > 0 ? (
                <>
                  <div className="perm-section-title danger">
                    <AlertTriangle size={13}/> Suspicious Keywords Detected
                  </div>
                  {Object.entries(stat.suspicious_keywords).map(([kw, count]) => (
                    <div key={kw} className="kw-row">
                      <span className="kw-name">{kw}</span>
                      <span className="kw-count">found in {count} file{count > 1 ? "s" : ""}</span>
                    </div>
                  ))}
                </>
              ) : (
                <div className="perm-empty"><CheckCircle size={20} color="#30d158"/> No suspicious keywords</div>
              )}
              {stat.hardcoded_urls?.length > 0 && (
                <>
                  <div className="perm-section-title" style={{marginTop:"1.2rem"}}>Hardcoded URLs</div>
                  {stat.hardcoded_urls.slice(0, 10).map((u, i) => <div key={i} className="url-row">{u}</div>)}
                </>
              )}
              {stat.hardcoded_ips?.length > 0 && (
                <>
                  <div className="perm-section-title danger" style={{marginTop:"1.2rem"}}>
                    <AlertTriangle size={13}/> Hardcoded IPs
                  </div>
                  {stat.hardcoded_ips.map((ip, i) => <div key={i} className="perm-row danger">{ip}</div>)}
                </>
              )}
            </div>
          )}
          {tab === "llm" && (
            <div className="tab-llm">
              {llm ? (
                <>
                  <div className="llm-model">🤖 Analysed by {llm.model}</div>
                  {[
                    { title: "Executive Threat Summary", content: llm.threat_summary },
                    { title: "Permission Analysis",      content: llm.permission_analysis },
                    { title: "Code Behaviour Analysis",  content: llm.code_analysis },
                    { title: "Plain English",            content: llm.plain_explanation },
                  ].map(({ title, content }) => content && (
                    <div key={title} className="llm-section">
                      <div className="llm-section-title">{title}</div>
                      <div className="llm-content">{content}</div>
                    </div>
                  ))}
                </>
              ) : (
                <div className="perm-empty" style={{flexDirection:"column",gap:"0.5rem"}}>
                  <Brain size={28} color="#636366"/>
                  <span>No LLM analysis available</span>
                  <span style={{fontSize:"0.75rem",color:"#636366"}}>Run locally with Ollama enabled</span>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── History row ───────────────────────────────────────────────────
function HistoryRow({ item, onClick, onDelete, apiOnline }) {
  const score = item.final_score ?? 0;
  const color = scoreColor(score);
  return (
    <div className="history-row" onClick={onClick}>
      <div className="hist-score" style={{ color, borderColor: color }}>{score}</div>
      <div className="hist-info">
        <div className="hist-apk">{item.apk_name}</div>
        <div className="hist-pkg">{item.package}</div>
      </div>
      <div className="hist-cat" style={{ color }}>
        {categoryIcon(item.category)} {item.category}
      </div>
      {apiOnline && (
        <button className="hist-del" onClick={e => { e.stopPropagation(); onDelete(item.apk_name?.replace(".apk","")) }}>
          <Trash2 size={13}/>
        </button>
      )}
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────
export default function App() {
  const [reports,    setReports]    = useState([]);
  const [stats,      setStats]      = useState(null);
  const [activeJob,  setActiveJob]  = useState(null);
  const [selected,   setSelected]   = useState(null);
  const [uploading,  setUploading]  = useState(false);
  const [useLLM,     setUseLLM]     = useState(false);
  const [error,      setError]      = useState("");
  const [apiOnline,  setApiOnline]  = useState(false);

  // ── Check API health ────────────────────────────────────────────
  const checkAPI = useCallback(async () => {
    try {
      await axios.get(`${API}/health`, { timeout: 3000 });
      setApiOnline(true);
      return true;
    } catch {
      setApiOnline(false);
      return false;
    }
  }, []);

  // ── Fetch history & stats ───────────────────────────────────────
  const refresh = useCallback(async () => {
    const online = await checkAPI();
    if (!online) {
      setReports(DEMO_REPORTS);
      setStats(DEMO_STATS);
      return;
    }
    try {
      const [r, s] = await Promise.all([
        axios.get(`${API}/reports`),
        axios.get(`${API}/stats`),
      ]);
      setReports(r.data);
      setStats(s.data);
    } catch {}
  }, [checkAPI]);

  useEffect(() => { refresh(); }, [refresh]);

  // ── Poll active job ─────────────────────────────────────────────
  useEffect(() => {
    if (!activeJob) return;
    const iv = setInterval(async () => {
      try {
        const { data } = await axios.get(`${API}/job/${activeJob.job_id}`);
        setActiveJob(data);
        if (data.status === "done") {
          setUploading(false);
          refresh();
          clearInterval(iv);
          setSelected(data.result);
        }
        if (data.status === "error") {
          setUploading(false);
          setError(data.error || "Analysis failed");
          clearInterval(iv);
        }
      } catch {}
    }, 1500);
    return () => clearInterval(iv);
  }, [activeJob?.job_id, refresh]);

  // ── Upload handler ──────────────────────────────────────────────
  const handleUpload = async (file) => {
    setError("");
    setUploading(true);
    const form = new FormData();
    form.append("file", file);
    try {
      const endpoint = useLLM ? "/analyse" : "/quick-score";
      const { data } = await axios.post(`${API}${endpoint}`, form);
      setActiveJob({ job_id: data.job_id, status: "queued", progress: 0, message: "Queued..." });
    } catch (e) {
      setUploading(false);
      setError(e.response?.data?.detail || "Upload failed");
    }
  };

  const handleDelete = async (apkName) => {
    try {
      await axios.delete(`${API}/report/${apkName}`);
      refresh();
    } catch {}
  };

  const handleRowClick = (item) => {
    if (!apiOnline) {
      if (item.apk_name === "Calculator.apk") {
        setSelected(DEMO_DETAIL_CALC);
      } else {
        setSelected(DEMO_DETAIL);
      }
      return;
    }
    axios.get(`${API}/report/${item.apk_name?.replace(".apk","")}`)
      .then(r => setSelected(r.data))
      .catch(() => {});
  };

  const StatPill = ({ label, value, color }) => (
    <div className="stat-pill">
      <span className="stat-val" style={{ color }}>{value}</span>
      <span className="stat-lbl">{label}</span>
    </div>
  );

  return (
    <div className="app">
      <header className="header">
        <div className="header-left">
          <Shield className="header-icon" size={28} />
          <div>
            <div className="header-title">APKGuard</div>
            <div className="header-sub">Banking APK Threat Intelligence</div>
          </div>
        </div>
        <div className="header-right">
          <div className={`api-status ${apiOnline ? "online" : "offline"}`}>
            {apiOnline ? <Wifi size={12}/> : <WifiOff size={12}/>}
            {apiOnline ? "API Live" : "Demo Mode"}
          </div>
          <div className="llm-toggle">
            <span>AI Analysis</span>
            <button className={`toggle-btn ${useLLM ? "on" : ""}`} onClick={() => setUseLLM(v => !v)}>
              <Brain size={12}/> {useLLM ? "ON" : "OFF"}
            </button>
          </div>
        </div>
      </header>

      <APIBanner online={apiOnline} />

      {stats && (
        <div className="stats-bar">
          <StatPill label="Total Scanned"  value={stats.total}      color="#fff" />
          <StatPill label="Critical"       value={stats.critical}   color="#ff2d55" />
          <StatPill label="High Risk"      value={stats.high_risk}  color="#ff9f0a" />
          <StatPill label="Suspicious"     value={stats.suspicious} color="#ffd60a" />
          <StatPill label="Low Risk"       value={stats.low_risk}   color="#30d158" />
          <StatPill label="Avg Score"      value={`${stats.avg_score}/100`} color="#64d2ff" />
        </div>
      )}

      <main className="main">
        <section className="upload-section">
          <UploadZone onUpload={handleUpload} loading={uploading} apiOnline={apiOnline} />
          {error && <div className="error-msg"><AlertTriangle size={14}/> {error}</div>}
          {activeJob && (activeJob.status === "running" || activeJob.status === "queued") && (
            <ProgressBar progress={activeJob.progress || 0} message={activeJob.message || "Starting..."} />
          )}
          <div className="mode-hint">
            {useLLM
              ? <><Brain size={12}/> AI mode: full LLM explanation (~3 min)</>
              : <><Zap size={12}/> Fast mode: ML score only (~90 sec)</>
            }
          </div>
        </section>

        <section className="history-section">
          <div className="history-header">
            <span>Scan History</span>
            <span className="history-count">{reports.length} APKs</span>
          </div>
          {reports.length === 0 ? (
            <div className="history-empty">No APKs analysed yet — upload one above</div>
          ) : (
            reports.map(r => (
              <HistoryRow
                key={r.apk_name}
                item={r}
                onClick={() => handleRowClick(r)}
                onDelete={handleDelete}
                apiOnline={apiOnline}
              />
            ))
          )}
        </section>
      </main>

      {selected && <ReportPanel report={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

