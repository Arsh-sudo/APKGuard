import express, { Request, Response } from "express";
import cors from "cors";
import path from "path";
import fs from "fs";
import multer from "multer";
import { createServer as createViteServer } from "vite";
import { parseAPKBuffer, generateLLMReport, APKReport } from "./src/analyzer";
import { mockReports } from "./src/lib/mockData";
import { VerdictCategory } from "./src/types";

const app = express();
const PORT = 3000;

// Structured CORS configuration
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow localhost, dev container host, Google Cloud Run domains, and origin-less requests
      if (!origin || origin.includes("localhost") || origin.includes("127.0.0.1") || origin.endsWith(".run.app")) {
        callback(null, true);
      } else {
        callback(null, true); // Permissive for preview iframe environments
      }
    },
    credentials: true,
  })
);

app.use(express.json());

// In-memory data stores
const reportsStore = new Map<string, APKReport>();
const jobsStore = new Map<
  string,
  {
    job_id: string;
    apk_name: string;
    original_name: string;
    status: "queued" | "running" | "done" | "error" | "cancelled";
    progress: number;
    current_step: number;
    message: string;
    logs: string[];
    result: APKReport | null;
    error: string | null;
    created_at: string;
    updated_at: string;
  }
>();

// Seed initial reports with standardized categories
for (const report of mockReports) {
  reportsStore.set(report.apk_name, report as any);
}

// Pre-seeded comprehensive specimen dossiers for instant triage
const seedBankingTrojan: APKReport = {
  apk_name: "BankingTrojan.apk",
  apk_size_kb: 312.4,
  analysed_at: "2026-05-20T23:46:56",
  manifest: {
    package: "krep.itmtd.ywtjexf",
    version_name: "1.0",
    version_code: "1",
    min_sdk: 21,
    target_sdk: 33,
    activities_count: 3,
    services_count: 2,
    receivers_count: 4,
    providers_count: 0,
    activities: ["com.bank.fake.MainActivity", "com.bank.fake.OverlayActivity", "com.bank.fake.CaptureActivity"],
    services: ["com.bank.fake.AccessibilityService", "com.bank.fake.BackgroundSyncService"],
    receivers: ["com.bank.fake.SMSReceiver", "com.bank.fake.BootReceiver", "com.bank.fake.AdminReceiver", "com.bank.fake.PushReceiver"],
    dangerous_permissions: [
      "READ_SMS", "SEND_SMS", "RECEIVE_SMS",
      "READ_CONTACTS", "READ_CALL_LOG",
      "READ_PHONE_STATE", "SYSTEM_ALERT_WINDOW",
      "RECEIVE_BOOT_COMPLETED", "BIND_ACCESSIBILITY_SERVICE"
    ],
    permissions: [
      "android.permission.READ_SMS", "android.permission.SEND_SMS",
      "android.permission.RECEIVE_SMS", "android.permission.READ_CONTACTS",
      "android.permission.READ_CALL_LOG", "android.permission.INTERNET",
      "android.permission.READ_PHONE_STATE", "android.permission.SYSTEM_ALERT_WINDOW",
      "android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.WAKE_LOCK",
      "android.permission.BIND_ACCESSIBILITY_SERVICE"
    ],
  },
  static_analysis: {
    total_java_files: 335,
    obfuscation_score: 110,
    obfuscation_flag: true,
    suspicious_keywords: {
      AccessibilityService: 2,
      DevicePolicyManager: 1,
      sendTextMessage: 3,
      getDeviceId: 2,
      overlay: 4,
      addJavascriptInterface: 1,
      HttpURLConnection: 5,
      WebView: 2,
      KeyLogger: 1
    },
    hardcoded_urls: ["http://185.234.xx.xx/gate.php", "http://update.malicious-c2.ru/cmd"],
    hardcoded_ips: ["185.234.xx.xx", "91.108.xx.xx"],
    native_lib_count: 0,
    native_libs: [],
    dex_count: 1,
    smali_file_count: 120,
    md5: "5d41402abc4b2a76b9719d911017c592",
    sha1: "2ef7bde608ce5404e97d5f042f95f89f1c232871",
    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  },
  heuristic_scoring: {
    heuristic_score: 100,
    category: "CRITICAL",
    reasons: [
      "Dangerous permission: READ_SMS (+15)",
      "Dangerous permission: SEND_SMS (+15)",
      "Dangerous permission: BIND_ACCESSIBILITY_SERVICE (+20)",
      "Suspicious code: AccessibilityService found in 2 file(s) (+15)",
      "Suspicious code: overlay found in 4 file(s) (+8)",
      "Dangerous permission: SYSTEM_ALERT_WINDOW (+18)",
    ],
  },
  ml_scoring: {
    ml_probability: 0.998,
    ml_score: 99.8,
    heuristic_score: 100,
    final_score: 99.9,
    category: "CRITICAL",
    model_confidence: 98.4,
    operating_threshold: 0.80,
    top_features: [
      { name: "perm::BIND_ACCESSIBILITY_SERVICE", importance: 0.94, impact: "positive", description: "Automated UI touch injection and keylogging vector", value: 1, present: true },
      { name: "perm::RECEIVE_SMS", importance: 0.89, impact: "positive", description: "Intercepts incoming bank 2FA SMS tokens", value: 1, present: true },
      { name: "api::onAccessibilityEvent", importance: 0.86, impact: "positive", description: "Surveils active foreground banking applications", value: 2, present: true },
      { name: "perm::SYSTEM_ALERT_WINDOW", importance: 0.82, impact: "positive", description: "Injects deceptive phishing overlays over banking apps", value: 1, present: true },
      { name: "api::sendTextMessage", importance: 0.78, impact: "positive", description: "Unauthorized SMS transmission routine", value: 3, present: true },
    ]
  },
  llm_analysis: {
    model: "APKGuard Threat Intelligence Engine",
    executive_summary: "Automated triage classified krep.itmtd.ywtjexf as a critical banking trojan (99.9/100). The specimen combines accessibility abuse, SMS interception, and screen overlay capabilities characteristic of the Hydra and Godfather trojan families. Immediate enterprise block recommended.",
    threat_mechanism: "The specimen requests BIND_ACCESSIBILITY_SERVICE to automate button clicks, prevent uninstallation, and capture keystrokes. It combines SYSTEM_ALERT_WINDOW with foreground application polling to inject counterfeit login overlays over legit banking apps. Intercepted 2FA credentials and SMS codes are transmitted to hardcoded C2 IPs.",
    plain_english_advisory: "This application is a dangerous banking malware sample. If installed, it can steal your banking login details, read two-factor authentication text messages, and take control of your phone screen. Do not install.",
    high_risk_permissions_context: [
      { permission: "android.permission.BIND_ACCESSIBILITY_SERVICE", context: "Permits automated screen scraping, keylogging, and silent button clicks." },
      { permission: "android.permission.RECEIVE_SMS", context: "Intercepts incoming bank OTPs and authorization codes." },
      { permission: "android.permission.SYSTEM_ALERT_WINDOW", context: "Draws deceptive counterfeit screens over banking apps." },
      { permission: "android.permission.READ_PHONE_STATE", context: "Extracts IMSI/IMEI identifiers for fraud operator tracking." }
    ],
    recommendations: [
      "Block package name krep.itmtd.ywtjexf globally across all corporate MDM profiles.",
      "Blacklist file hash across endpoint detection agents.",
      "Force immediate credential resets for users whose devices have exhibited this binary."
    ],
    evasion_techniques: [
      "Dalvik identifier packing and entropy obfuscation",
      "Direct hardcoded IP sockets bypassing domain reputation filters"
    ],
    threat_summary: "VERDICT: Critical Threat / Active Banking Trojan (99.9/100)\nTHREAT TYPE: Android Banking Credential Harvester\nKEY RISKS:\n• Intercepts 2FA SMS tokens and OTP codes\n• Abuses AccessibilityService for automated UI clicks and keylogging\n• Injects fake overlay windows over banking apps\nRECOMMENDED ACTION: Block immediately and revoke all corporate device access.",
    permission_analysis: "The app requests READ_SMS and RECEIVE_SMS to bypass banking two-factor authentication, plus SYSTEM_ALERT_WINDOW for fake login overlay screens.",
    code_analysis: "Contains hardcoded C2 server endpoints, dynamic JavaScript interfaces, and accessibility event listeners to exfiltrate keystrokes and account credentials.",
    plain_explanation: "This app is an aggressive banking trojan designed to steal bank passwords and intercept SMS security codes. It should be removed immediately.",
    ciso_recommendation: "ENFORCE GLOBAL QUARANTINE: Deploy blacklist rule across enterprise MDM and report sample to national CERT.",
  },
};

const seedCalculator: APKReport = {
  apk_name: "Calculator.apk",
  apk_size_kb: 6571.1,
  analysed_at: "2026-05-20T22:19:42",
  manifest: {
    package: "com.google.android.calculator",
    version_name: "8.1",
    version_code: "81001",
    min_sdk: 23,
    target_sdk: 33,
    activities_count: 2,
    services_count: 0,
    receivers_count: 1,
    providers_count: 0,
    activities: ["com.android.calculator2.Calculator"],
    services: [],
    receivers: ["com.android.calculator2.CalculatorWidgetProvider"],
    dangerous_permissions: [],
    permissions: ["android.permission.INTERNET", "android.permission.WAKE_LOCK"],
  },
  static_analysis: {
    total_java_files: 3538,
    obfuscation_score: 12,
    obfuscation_flag: false,
    suspicious_keywords: { Base64: 8, DES: 19, overlay: 4, getRuntime: 4 },
    hardcoded_urls: [],
    hardcoded_ips: [],
    native_lib_count: 2,
    native_libs: ["libcalculator.so", "libmath.so"],
    dex_count: 2,
    smali_file_count: 240,
    md5: "7d018cb1a8c0efcd2549a716f9f38f42",
    sha1: "8f5b822d6409890a3c26781297e5513abcb08e33",
    sha256: "b45c26b9a89d7658742918451101ab8762514109867510294716091248761234",
  },
  heuristic_scoring: {
    heuristic_score: 25,
    category: "LOW_RISK",
    reasons: [
      "Standard math library utility strings detected",
      "No dangerous system permissions declared"
    ],
  },
  ml_scoring: {
    ml_probability: 0.011,
    ml_score: 1.1,
    heuristic_score: 25,
    final_score: 10.5,
    category: "LOW_RISK",
    model_confidence: 96.2,
    operating_threshold: 0.80,
    top_features: [
      { name: "perm::BIND_ACCESSIBILITY_SERVICE", importance: 0.94, impact: "negative", description: "Automated UI touch injection vector", value: 0, present: false },
      { name: "perm::RECEIVE_SMS", importance: 0.89, impact: "negative", description: "Incoming bank 2FA SMS intercept vector", value: 0, present: false },
      { name: "perm::SYSTEM_ALERT_WINDOW", importance: 0.82, impact: "negative", description: "Deceptive overlay injection vector", value: 0, present: false }
    ]
  },
  llm_analysis: {
    model: "APKGuard Threat Intelligence Engine",
    executive_summary: "Automated analysis confirmed com.google.android.calculator as a benign utility application with a low risk score of 10.5/100. No unauthorized SMS interception, accessibility abuse, or suspicious command-and-control signatures were identified.",
    threat_mechanism: "Legitimate mathematical calculator application. Bytecode signatures reflect standard Android framework utility components without malicious capabilities.",
    plain_english_advisory: "This application is verified as clean and safe to use. It does not request dangerous privileges or exhibit harmful behavior.",
    high_risk_permissions_context: [],
    recommendations: [
      "Safe for general enterprise deployment on corporate mobile devices."
    ],
    evasion_techniques: [],
    threat_summary: "VERDICT: This app is SAFE — Legitimate Google Calculator (10.5/100).\nTHREAT TYPE: Legitimate Android Application\nKEY RISKS: None identified\nRECOMMENDED ACTION: Safe to allow on all devices.",
    permission_analysis: "No dangerous permissions declared — standard minimal footprint.",
    code_analysis: "Base64 and math helper strings belong to standard utility calculations. No malicious intent detected.",
    plain_explanation: "This is Google Calculator. Score 10.5/100 confirms it is safe to use.",
    ciso_recommendation: "APPROVED: Meets baseline security standards for deployment on managed devices.",
  },
};

const seedTorch: APKReport = {
  apk_name: "icon-torch-flashlight.apk",
  apk_size_kb: 49.4,
  analysed_at: "2026-05-24T17:34:59",
  manifest: {
    package: "com.bright.torch.flashlight.tool",
    version_name: "1.2.0",
    version_code: "12",
    min_sdk: 21,
    target_sdk: 33,
    activities_count: 2,
    services_count: 2,
    receivers_count: 2,
    providers_count: 0,
    activities: ["com.bright.torch.MainActivity", "com.bright.torch.OverlayActivity"],
    services: ["com.bright.torch.FlashService", "com.bright.torch.DaemonService"],
    receivers: ["com.bright.torch.BootReceiver", "com.bright.torch.PackageChangeReceiver"],
    dangerous_permissions: ["SYSTEM_ALERT_WINDOW", "RECEIVE_BOOT_COMPLETED", "CAMERA"],
    permissions: [
      "android.permission.CAMERA",
      "android.permission.FLASHLIGHT",
      "android.permission.SYSTEM_ALERT_WINDOW",
      "android.permission.RECEIVE_BOOT_COMPLETED",
      "android.permission.WAKE_LOCK",
      "android.permission.INTERNET",
      "android.permission.ACCESS_NETWORK_STATE"
    ],
  },
  static_analysis: {
    total_java_files: 42,
    hardcoded_urls: ["http://api.stats-collector.net/v1/ping"],
    hardcoded_ips: ["198.51.100.45"],
    suspicious_keywords: { WindowManager: 4, getSystemService: 8, HttpURLConnection: 2, Base64: 3 },
    obfuscation_score: 22,
    obfuscation_flag: false,
    native_lib_count: 0,
    native_libs: [],
    dex_count: 1,
    smali_file_count: 58,
    md5: "a3d2019c8f2b7405e3f1947bca821094",
    sha1: "9b8402a76f2d5e3c8a91b2c3d4e5f60718293a4b",
    sha256: "7f9c2d1b8e4a5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcd",
  },
  heuristic_scoring: {
    heuristic_score: 68,
    category: "HIGH_RISK",
    reasons: [
      "Flashlight utility requests SYSTEM_ALERT_WINDOW (overlay permission) with no operational justification",
      "Auto-starts in background on device boot via RECEIVE_BOOT_COMPLETED",
      "Contacts remote collector server while maintaining active background daemon service"
    ],
  },
  ml_scoring: {
    ml_probability: 0.732,
    ml_score: 73.2,
    heuristic_score: 68,
    final_score: 73.2,
    category: "HIGH_RISK",
    model_confidence: 88.6,
    operating_threshold: 0.80,
    top_features: [
      { name: "perm::SYSTEM_ALERT_WINDOW", importance: 0.89, impact: "positive", description: "Deceptive overlay window injection over banking logins", value: 1, present: true },
      { name: "perm::RECEIVE_BOOT_COMPLETED", importance: 0.81, impact: "positive", description: "Background auto-launch persistence", value: 1, present: true },
      { name: "net::hardcoded_ip_ratio", importance: 0.63, impact: "positive", description: "Direct socket connections bypassing DNS resolution", value: 1, present: true },
      { name: "perm::CAMERA", importance: 0.65, impact: "positive", description: "Hardware camera / LED strobe activation", value: 1, present: true }
    ]
  },
  llm_analysis: {
    model: "APKGuard Threat Intelligence Engine",
    executive_summary: "Automated analysis flagged com.bright.torch.flashlight.tool as a high-risk suspicious dropper utility (73.2/100). The specimen masquerades as a flashlight while establishing background persistence and deceptive overlay capabilities.",
    threat_mechanism: "A genuine flashlight app only requires camera flash control. Declaring SYSTEM_ALERT_WINDOW and RECEIVE_BOOT_COMPLETED is a common pattern in trojan droppers to monitor foreground activities and overlay fake login screens over targeted financial apps.",
    plain_english_advisory: "This flashlight app asks for dangerous permissions it does not need, including permission to draw over other apps and run in the background on startup. Exercise caution.",
    high_risk_permissions_context: [
      { permission: "android.permission.SYSTEM_ALERT_WINDOW", context: "Allows creating window overlays on top of other running applications." },
      { permission: "android.permission.RECEIVE_BOOT_COMPLETED", context: "Auto-starts background services when device turns on." }
    ],
    recommendations: [
      "Quarantine binary on managed enterprise devices.",
      "Conduct network sandbox inspection on outbound traffic to 198.51.100.45."
    ],
    evasion_techniques: [
      "Trojan masquerading as a utility tool"
    ],
    threat_summary: "VERDICT: High Risk / Suspicious Overlay Utility (73.2/100).\nTHREAT CLASSIFICATION: Trojanised Flashlight Utility.\nPRIMARY OBJECTIVE: Masquerading as a harmless flashlight while establishing background persistence and deceptive overlay capabilities.",
    permission_analysis: "A genuine flashlight app only needs camera flash access. Requesting SYSTEM_ALERT_WINDOW and RECEIVE_BOOT_COMPLETED is a well-documented tactic used by banking trojan droppers to display phishing login prompts over legitimate banking applications.",
    code_analysis: "Source routines instantiate WindowManager overlay params with TYPE_APPLICATION_OVERLAY and maintain a persistent background DaemonService connecting to an untrusted external IP.",
    plain_explanation: "This flashlight app asks for dangerous permissions it should not need, such as permission to draw over other apps and run in the background. In banking cybersecurity, this pattern is frequently used to steal credentials.",
    ciso_recommendation: "BLOCK ON MANAGED FLEET: High risk of dropper activity. Recommend user notification and removal.",
  },
};

reportsStore.set("BankingTrojan.apk", seedBankingTrojan);
reportsStore.set("Calculator.apk", seedCalculator);
reportsStore.set("icon-torch-flashlight.apk", seedTorch);

// Multer setup using diskStorage to prevent memory exhaustion / ZIP bombs
const UPLOADS_DIR = "/tmp/apkguard_uploads";
try {
  if (!fs.existsSync(UPLOADS_DIR)) {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
  }
} catch {
  // fallback if /tmp is not writable
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, fs.existsSync(UPLOADS_DIR) ? UPLOADS_DIR : ".");
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, "apk-" + uniqueSuffix + ".apk");
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB limit
});

// Sliding window in-memory rate limiter
const rateLimiter = (() => {
  const windowMs = 60 * 1000; // 1 minute
  const maxReqs = 25;
  const ipMap = new Map<string, number[]>();

  return (req: Request, res: Response, next: () => void) => {
    const ip = req.ip || req.socket.remoteAddress || "127.0.0.1";
    const now = Date.now();
    const timestamps = (ipMap.get(ip) || []).filter((t) => now - t < windowMs);
    if (timestamps.length >= maxReqs) {
      return res.status(429).json({ detail: "Upload rate limit exceeded. Please wait a minute." });
    }
    timestamps.push(now);
    ipMap.set(ip, timestamps);
    next();
  };
})();

// API Routes
app.get("/api/health", (req: Request, res: Response) => {
  res.json({
    api: "ok",
    model: "loaded",
    timestamp: new Date().toISOString(),
  });
});

app.get("/health", (req: Request, res: Response) => {
  res.json({
    api: "ok",
    model: "loaded",
    timestamp: new Date().toISOString(),
  });
});

app.get("/stats", (req: Request, res: Response) => {
  const allReports = Array.from(reportsStore.values());
  const total = allReports.length;
  if (total === 0) {
    return res.json({ total: 0, critical: 0, high_risk: 0, suspicious: 0, low_risk: 0, avg_score: 0, with_llm: 0 });
  }

  const normalize = (cat: string): VerdictCategory => {
    const c = String(cat || "").toUpperCase().replace(/[\s_-]+/g, "_");
    if (c.includes("CRITICAL")) return "CRITICAL";
    if (c.includes("HIGH")) return "HIGH_RISK";
    if (c.includes("SUSPICIOUS") || c.includes("MEDIUM")) return "SUSPICIOUS";
    return "LOW_RISK";
  };

  const categories = allReports.map((r) => normalize(r.ml_scoring?.category));
  const avgScore = Math.round((allReports.reduce((acc, r) => acc + (r.ml_scoring?.final_score || 0), 0) / total) * 10) / 10;

  res.json({
    total,
    critical: categories.filter((c) => c === "CRITICAL").length,
    high_risk: categories.filter((c) => c === "HIGH_RISK").length,
    suspicious: categories.filter((c) => c === "SUSPICIOUS").length,
    low_risk: categories.filter((c) => c === "LOW_RISK").length,
    avg_score: avgScore,
    with_llm: allReports.filter((r) => r.llm_analysis !== null).length,
  });
});

// Return complete reports directly to eliminate 30-request thundering herd
app.get("/reports", (req: Request, res: Response) => {
  const allReports = Array.from(reportsStore.values());
  allReports.sort((a, b) => (b.analysed_at || "").localeCompare(a.analysed_at || ""));
  res.json(allReports);
});

app.get("/report/:apk_name", (req: Request, res: Response) => {
  const apkParam = String(req.params.apk_name || "");
  const name = apkParam.endsWith(".apk") ? apkParam : `${apkParam}.apk`;
  const report = reportsStore.get(name) || reportsStore.get(apkParam);

  if (!report) {
    return res.status(404).json({ detail: `No report found for ${apkParam}` });
  }
  res.json(report);
});

app.delete("/report/:apk_name", (req: Request, res: Response) => {
  const apkParam = String(req.params.apk_name || "");
  const name = apkParam.endsWith(".apk") ? apkParam : `${apkParam}.apk`;
  reportsStore.delete(name);
  reportsStore.delete(apkParam);
  res.json({ message: `Report for ${apkParam} deleted` });
});

app.get("/jobs", (req: Request, res: Response) => {
  res.json(Array.from(jobsStore.values()));
});

// Strict job polling — returns genuine 404 if job does not exist
app.get("/job/:job_id", (req: Request, res: Response) => {
  const jobId = String(req.params.job_id || "");
  const job = jobsStore.get(jobId);

  if (!job) {
    return res.status(404).json({ detail: "Job not found" });
  }
  res.json(job);
});

app.post("/job/:job_id/cancel", (req: Request, res: Response) => {
  const jobId = String(req.params.job_id || "");
  const job = jobsStore.get(jobId);
  if (!job) {
    return res.status(404).json({ detail: "Job not found" });
  }
  if (job.status === "running" || job.status === "queued") {
    job.status = "cancelled";
    job.message = "Analysis job cancelled by user";
    job.logs.push(`[${new Date().toLocaleTimeString()}] [USER] Analysis pipeline aborted by user.`);
    job.updated_at = new Date().toISOString();
  }
  res.json({ message: "Job cancelled", job });
});

// Async pipeline handler for APK analysis
async function runAnalysisPipeline(
  jobId: string,
  buffer: Buffer,
  apkName: string,
  originalName: string,
  runLlm: boolean
) {
  const addLog = (tag: string, text: string) => {
    const job = jobsStore.get(jobId);
    if (job) {
      const timeStr = new Date().toLocaleTimeString();
      job.logs.push(`[${timeStr}] [${tag}] ${text}`);
      job.updated_at = new Date().toISOString();
    }
  };

  const updateJob = (
    status: "queued" | "running" | "done" | "error" | "cancelled",
    progress: number,
    current_step: number,
    message: string
  ) => {
    const job = jobsStore.get(jobId);
    if (job) {
      if (job.status === "cancelled") return;
      job.status = status;
      job.progress = progress;
      job.current_step = current_step;
      job.message = message;
      job.updated_at = new Date().toISOString();
    }
  };

  try {
    addLog("INIT", `Starting ingestion for ${originalName} (${Math.round(buffer.length / 1024)} KB)`);
    updateJob("running", 15, 1, "Validating APK container & decompiling Dalvik bytecode...");
    addLog("ZIP", "Verified PK 03 04 zip magic header bytes");
    await new Promise((resolve) => setTimeout(resolve, 350));

    if (jobsStore.get(jobId)?.status === "cancelled") return;

    updateJob("running", 40, 2, "Decompiling AndroidManifest.xml and Dalvik executables...");
    addLog("DECOMPILE", "apktool disassembly initiated: classes.dex -> smali intermediate representation");

    const { manifest, staticAnalysis, heuristicScoring, mlScoring } = parseAPKBuffer(buffer, originalName);
    addLog("MANIFEST", `Package extracted: ${manifest.package} (target SDK ${manifest.target_sdk || 33})`);
    addLog("PERMISSIONS", `Found ${manifest.permissions.length} permissions (${manifest.dangerous_permissions.length} dangerous)`);

    await new Promise((resolve) => setTimeout(resolve, 450));
    if (jobsStore.get(jobId)?.status === "cancelled") return;

    updateJob("running", 70, 3, "Computing static threat attribution vectors & Drebin benchmarks...");
    addLog("VECTORS", `Inference executed: Score ${mlScoring.final_score}/100, Verdict: ${mlScoring.category}`);
    addLog("FEATURES", `Key indicators: ${(mlScoring.top_features || []).slice(0, 3).map((f) => f.name).join(", ")}`);

    await new Promise((resolve) => setTimeout(resolve, 500));
    if (jobsStore.get(jobId)?.status === "cancelled") return;

    let llmAnalysis: any = null;
    if (runLlm) {
      updateJob("running", 88, 4, "Connecting to AI security explainer engine...");
      addLog("LLM_GEN", "Generating structured threat intelligence summary & CISO brief...");
      llmAnalysis = await generateLLMReport({
        package: manifest.package,
        finalScore: mlScoring.final_score,
        category: mlScoring.category,
        dangerousPerms: manifest.dangerous_permissions,
        keywords: Object.keys(staticAnalysis.suspicious_keywords),
        urls: staticAnalysis.hardcoded_urls,
        ips: staticAnalysis.hardcoded_ips,
      });
      addLog("LLM_DONE", "AI Threat Intelligence analysis generated successfully.");
    } else {
      updateJob("running", 95, 4, "Finalizing report without LLM generation...");
      addLog("SKIP_LLM", "Quick-score mode selected. Bypassing GenAI synthesis.");
    }

    const report: APKReport = {
      apk_name: originalName,
      apk_size_kb: Math.round((buffer.length / 1024) * 10) / 10,
      analysed_at: new Date().toISOString(),
      manifest,
      static_analysis: staticAnalysis,
      heuristic_scoring: heuristicScoring,
      ml_scoring: mlScoring,
      llm_analysis: llmAnalysis,
    };

    reportsStore.set(originalName, report);

    const job = jobsStore.get(jobId);
    if (job && job.status !== "cancelled") {
      job.status = "done";
      job.progress = 100;
      job.current_step = 4;
      job.message = "Analysis complete";
      job.result = report;
      job.updated_at = new Date().toISOString();
      addLog("COMPLETE", `Pipeline finished. Report ready for review: ${originalName}`);
    }
  } catch (err: any) {
    console.error("Pipeline error:", err);
    const job = jobsStore.get(jobId);
    if (job && job.status !== "cancelled") {
      job.status = "error";
      job.error = err.message || "Failed to analyze APK";
      job.message = `Pipeline failed: ${err.message}`;
      job.updated_at = new Date().toISOString();
      addLog("ERROR", `Pipeline failure: ${err.message}`);
    }
  }
}

// Upload & Analyze endpoints
app.post("/analyse", rateLimiter, upload.single("file"), (req: Request, res: Response) => {
  if (!req.file) {
    return res.status(400).json({ detail: "No file uploaded" });
  }

  const originalName = req.file.originalname || "unknown.apk";
  if (!originalName.toLowerCase().endsWith(".apk")) {
    try { fs.unlinkSync(req.file.path); } catch {}
    return res.status(400).json({ detail: "Only .apk files are accepted" });
  }

  let buffer: Buffer;
  try {
    buffer = fs.readFileSync(req.file.path);
  } catch (err: any) {
    return res.status(500).json({ detail: `Failed to read uploaded file: ${err.message}` });
  } finally {
    try { fs.unlinkSync(req.file.path); } catch {}
  }

  // Strictly check magic bytes (PK\x03\x04 = 0x50, 0x4B, 0x03, 0x04)
  const isZipOrApk = buffer.length >= 4 && buffer[0] === 0x50 && buffer[1] === 0x4b && buffer[2] === 0x03 && buffer[3] === 0x04;

  if (!isZipOrApk) {
    return res.status(400).json({ detail: "Not a valid APK file (invalid ZIP magic bytes)" });
  }

  const jobId = Math.random().toString(36).substring(2, 14);
  const runLlm = req.body?.run_llm !== false && req.body?.run_llm !== "false";

  jobsStore.set(jobId, {
    job_id: jobId,
    apk_name: originalName,
    original_name: originalName,
    status: "queued",
    progress: 5,
    current_step: 1,
    message: "Queued for analysis",
    logs: [
      `[${new Date().toLocaleTimeString()}] [SYSTEM] Job initialized. Target: ${originalName}`,
      `[${new Date().toLocaleTimeString()}] [WORKER] Assigned worker node to pipeline #${jobId}`,
    ],
    result: null,
    error: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });

  // Run pipeline asynchronously
  runAnalysisPipeline(jobId, buffer, originalName, originalName, runLlm);

  res.json({
    job_id: jobId,
    message: "Analysis started",
    poll_url: `/job/${jobId}`,
  });
});

app.post("/quick-score", rateLimiter, upload.single("file"), (req: Request, res: Response) => {
  if (!req.file) {
    return res.status(400).json({ detail: "No file uploaded" });
  }

  const originalName = req.file.originalname || "unknown.apk";
  if (!originalName.toLowerCase().endsWith(".apk")) {
    try { fs.unlinkSync(req.file.path); } catch {}
    return res.status(400).json({ detail: "Only .apk files are accepted" });
  }

  let buffer: Buffer;
  try {
    buffer = fs.readFileSync(req.file.path);
  } catch (err: any) {
    return res.status(500).json({ detail: `Failed to read uploaded file: ${err.message}` });
  } finally {
    try { fs.unlinkSync(req.file.path); } catch {}
  }

  const isZipOrApk = buffer.length >= 4 && buffer[0] === 0x50 && buffer[1] === 0x4b && buffer[2] === 0x03 && buffer[3] === 0x04;

  if (!isZipOrApk) {
    return res.status(400).json({ detail: "Not a valid APK file (invalid ZIP magic bytes)" });
  }

  const jobId = Math.random().toString(36).substring(2, 14);

  jobsStore.set(jobId, {
    job_id: jobId,
    apk_name: originalName,
    original_name: originalName,
    status: "queued",
    progress: 5,
    current_step: 1,
    message: "Queued for quick score",
    logs: [
      `[${new Date().toLocaleTimeString()}] [SYSTEM] Quick scoring job initialized for ${originalName}`,
    ],
    result: null,
    error: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });

  runAnalysisPipeline(jobId, buffer, originalName, originalName, false);

  res.json({
    job_id: jobId,
    message: "Quick score started",
    poll_url: `/job/${jobId}`,
  });
});

// Vite middleware & Production SPA Static Serving
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    // Safe universal SPA fallback handler across all Express versions
    app.use((req: Request, res: Response) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`APKGuard server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
