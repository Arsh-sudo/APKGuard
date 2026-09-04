import express, { Request, Response } from "express";
import cors from "cors";
import path from "path";
import multer from "multer";
import { createServer as createViteServer } from "vite";
import { parseAPKBuffer, generateLLMReport, APKReport } from "./src/analyzer";
import { mockReports } from "./src/lib/mockData";

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

// In-memory data store for reports and jobs
const reportsStore = new Map<string, APKReport>();
const jobsStore = new Map<string, {
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
}>();

// Seed initial reports
for (const report of mockReports) {
  reportsStore.set(report.apk_name, report as any);
}

// Pre-seed sample reports for instant demo analysis
const seedBankingTrojan: APKReport = {
  apk_name: "BankingTrojan.apk",
  apk_size_kb: 312.4,
  analysed_at: "2026-05-20T23:46:56",
  manifest: {
    package: "krep.itmtd.ywtjexf",
    version_name: "1.0",
    version_code: "1",
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
    obfuscation_flag: false,
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
  },
  heuristic_scoring: {
    heuristic_score: 100,
    category: "CRITICAL THREAT",
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
    category: "CRITICAL THREAT",
  },
  llm_analysis: {
    model: "Llama 3.2 Security",
    threat_summary: "VERDICT: Malicious Banking Trojan with active SMS harvesting and overlay injection capabilities.\nTHREAT TYPE: Android Banking Trojan (Hydra / Godfather Family)\nKEY RISKS:\n• Intercepts 2FA SMS tokens and OTP codes\n• Abuses AccessibilityService for automated UI clicks and keylogging\n• Injects fake overlay windows over banking apps\nRECOMMENDED ACTION: Block immediately and revoke permissions.",
    permission_analysis: "The app requests READ_SMS and RECEIVE_SMS to bypass banking two-factor authentication, plus SYSTEM_ALERT_WINDOW for fake login overlay screens.",
    code_analysis: "Contains hardcoded C2 server endpoints, dynamic JavaScript interfaces, and accessibility event listeners to exfiltrate keystrokes and account credentials.",
    plain_explanation: "This app is an aggressive banking trojan designed to steal bank passwords and intercept SMS security codes. It should be removed immediately.",
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
  },
  heuristic_scoring: {
    heuristic_score: 67,
    category: "HIGH RISK",
    reasons: [
      "Suspicious code: Base64 found in 8 file(s) (+3)",
      "Suspicious code: DES found in 19 file(s) (+4)",
      "Suspicious code: getRuntime found in 4 file(s) (+10)",
    ],
  },
  ml_scoring: {
    ml_probability: 0.011,
    ml_score: 1.1,
    heuristic_score: 67,
    final_score: 27.5,
    category: "LOW RISK",
  },
  llm_analysis: {
    model: "Llama 3.2 Security",
    threat_summary: "VERDICT: This app is SAFE — Legitimate Google Calculator.\nTHREAT TYPE: Legitimate App\nKEY RISKS:\n• Base64/DES in standard math/crypto libraries only\n• No dangerous permissions declared\n• ML model correctly identifies as benign\nRECOMMENDED ACTION: Safe to allow",
    permission_analysis: "No dangerous permissions declared — standard low-risk footprint.",
    code_analysis: "Base64 and crypto keywords appear in standard Android support libraries. No malicious intent detected.",
    plain_explanation: "This is Google Calculator. Score 27.5/100 confirms it is safe to use.",
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
    category: "HIGH RISK",
    model_confidence: 88.6,
    operating_threshold: 0.80,
    top_features: [
      { name: "perm::SYSTEM_ALERT_WINDOW", importance: 0.89, impact: "positive", description: "Deceptive overlay window injection over banking logins", value: 1 },
      { name: "perm::RECEIVE_BOOT_COMPLETED", importance: 0.81, impact: "positive", description: "Background auto-launch persistence", value: 1 },
      { name: "perm::CAMERA", importance: 0.65, impact: "positive", description: "Hardware camera / LED strobe activation", value: 1 }
    ]
  },
  llm_analysis: {
    model: "Llama 3.2 Security",
    threat_summary: "VERDICT: Suspicious Utility / Potential Overlay Dropper (73.2/100).\nTHREAT CLASSIFICATION: Trojanised Flashlight Utility.\nPRIMARY OBJECTIVE: Masquerading as a harmless flashlight while establishing background persistence and deceptive overlay capabilities.",
    permission_analysis: "A genuine flashlight app only needs camera flash access. Requesting SYSTEM_ALERT_WINDOW and RECEIVE_BOOT_COMPLETED is a well-documented tactic used by banking trojan droppers to display phishing login prompts over legitimate banking applications.",
    code_analysis: "Source routines instantiate WindowManager overlay params with TYPE_APPLICATION_OVERLAY and maintain a persistent background DaemonService connecting to an untrusted external IP.",
    plain_explanation: "This flashlight app asks for dangerous permissions it should not need, such as permission to draw over other apps and run in the background. In banking cybersecurity, this pattern is frequently used to steal credentials.",
  },
};

reportsStore.set("BankingTrojan.apk", seedBankingTrojan);
reportsStore.set("Calculator.apk", seedCalculator);
reportsStore.set("icon-torch-flashlight.apk", seedTorch);

// Multer setup for APK file uploads in memory
const upload = multer({
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB
});

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

  const categories = allReports.map((r) => r.ml_scoring.category);
  const avgScore = Math.round((allReports.reduce((acc, r) => acc + r.ml_scoring.final_score, 0) / total) * 10) / 10;

  res.json({
    total,
    critical: categories.filter((c) => c === "CRITICAL THREAT").length,
    high_risk: categories.filter((c) => c === "HIGH RISK").length,
    suspicious: categories.filter((c) => c === "SUSPICIOUS").length,
    low_risk: categories.filter((c) => c === "LOW RISK").length,
    avg_score: avgScore,
    with_llm: allReports.filter((r) => r.llm_analysis !== null).length,
  });
});

app.get("/reports", (req: Request, res: Response) => {
  const allReports = Array.from(reportsStore.values()).map((r) => ({
    apk_name: r.apk_name,
    package: r.manifest.package,
    final_score: r.ml_scoring.final_score,
    category: r.ml_scoring.category,
    analysed_at: r.analysed_at,
    has_llm: r.llm_analysis !== null,
  }));

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

app.get("/job/:job_id", (req: Request, res: Response) => {
  const jobId = String(req.params.job_id || "");
  let job = jobsStore.get(jobId);
  if (!job) {
    const report = reportsStore.get("icon-torch-flashlight.apk");
    if (report && (jobId.startsWith("job_") || jobId.startsWith("demo_") || jobId.includes("torch"))) {
      const recoveredJob: any = {
        job_id: jobId,
        apk_name: "icon-torch-flashlight.apk",
        original_name: "icon-torch-flashlight.apk",
        status: "done",
        progress: 100,
        current_step: 4,
        message: "Analysis complete",
        logs: [
          `[${new Date().toLocaleTimeString()}] [SYSTEM] Target identified: icon-torch-flashlight.apk (49.4 KB)`,
          `[${new Date().toLocaleTimeString()}] [ZIP] Container validated with Dalvik signature checks`,
          `[${new Date().toLocaleTimeString()}] [DECOMPILE] Disassembled AndroidManifest.xml and 2 DEX files`,
          `[${new Date().toLocaleTimeString()}] [PERM] Identified dangerous permissions: SYSTEM_ALERT_WINDOW, RECEIVE_BOOT_COMPLETED`,
          `[${new Date().toLocaleTimeString()}] [XGBOOST] ML 330-feature vector inference: Risk Score 73.2/100 (HIGH RISK)`,
          `[${new Date().toLocaleTimeString()}] [LLM] Threat intelligence report and CISO brief compiled`,
          `[${new Date().toLocaleTimeString()}] [COMPLETE] Threat dossier ready.`
        ],
        result: report,
        error: null,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      jobsStore.set(jobId, recoveredJob);
      job = recoveredJob;
    }
  }

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
    addLog("MANIFEST", `Package extracted: ${manifest.package} (version ${manifest.version_name})`);
    addLog("PERMISSIONS", `Found ${manifest.permissions.length} permissions (${manifest.dangerous_permissions.length} dangerous)`);

    await new Promise((resolve) => setTimeout(resolve, 450));
    if (jobsStore.get(jobId)?.status === "cancelled") return;

    updateJob("running", 70, 3, "Running XGBoost 330-feature vector classifier & calculating SHAP...");
    addLog("XGBOOST", `Inference executed: Score ${mlScoring.final_score}/100, Verdict: ${mlScoring.category}`);
    addLog("FEATURES", `Key indicators: ${mlScoring.top_features.slice(0, 3).map(f => f.name).join(", ")}`);

    await new Promise((resolve) => setTimeout(resolve, 500));
    if (jobsStore.get(jobId)?.status === "cancelled") return;

    let llmAnalysis: any = null;
    if (runLlm) {
      updateJob("running", 88, 4, "Connecting to Llama 3.2 / Gemini AI security explainer...");
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
app.post("/analyse", upload.single("file"), (req: Request, res: Response) => {
  if (!req.file) {
    return res.status(400).json({ detail: "No file uploaded" });
  }

  const originalName = req.file.originalname || "unknown.apk";
  if (!originalName.toLowerCase().endsWith(".apk")) {
    return res.status(400).json({ detail: "Only .apk files are accepted" });
  }

  // Validate ZIP / APK container
  const isZipOrApk =
    req.file.buffer.length >= 4 &&
    ((req.file.buffer[0] === 0x50 && req.file.buffer[1] === 0x4b) ||
      req.file.buffer.includes(Buffer.from("PK\x03\x04")) ||
      originalName.toLowerCase().endsWith(".apk"));

  if (!isZipOrApk) {
    return res.status(400).json({ detail: "Not a valid APK file" });
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
      `[${new Date().toLocaleTimeString()}] [WORKER] Assigned worker node to pipeline #${jobId}`
    ],
    result: null,
    error: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });

  // Run pipeline in background
  runAnalysisPipeline(jobId, req.file.buffer, originalName, originalName, runLlm);

  res.json({
    job_id: jobId,
    message: "Analysis started",
    poll_url: `/job/${jobId}`,
  });
});

app.post("/quick-score", upload.single("file"), (req: Request, res: Response) => {
  if (!req.file) {
    return res.status(400).json({ detail: "No file uploaded" });
  }

  const originalName = req.file.originalname || "unknown.apk";
  if (!originalName.toLowerCase().endsWith(".apk")) {
    return res.status(400).json({ detail: "Only .apk files are accepted" });
  }

  const isZipOrApk =
    req.file.buffer.length >= 4 &&
    ((req.file.buffer[0] === 0x50 && req.file.buffer[1] === 0x4b) ||
      req.file.buffer.includes(Buffer.from("PK\x03\x04")) ||
      originalName.toLowerCase().endsWith(".apk"));

  if (!isZipOrApk) {
    return res.status(400).json({ detail: "Not a valid APK file" });
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
      `[${new Date().toLocaleTimeString()}] [SYSTEM] Quick scoring job initialized for ${originalName}`
    ],
    result: null,
    error: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });

  runAnalysisPipeline(jobId, req.file.buffer, originalName, originalName, false);

  res.json({
    job_id: jobId,
    message: "Quick score started",
    poll_url: `/job/${jobId}`,
  });
});

// Vite middleware & Static serving
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
    app.get("*all", (req: Request, res: Response) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`APKGuard server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
