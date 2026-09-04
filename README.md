# APKGuard — Banking APK Threat Intelligence Platform

**High-throughput static analysis, Drebin-aligned feature attribution, and GenAI-powered threat reporting for Android banking applications.**

APKGuard inspects Android application packages (APKs) to identify banking trojans, deceptive overlay droppers, and credential harvest malware. It performs deterministic static analysis on Dalvik bytecode and Android manifests, scores threat indicators against established malware taxonomy vectors, and synthesizes actionable CISO threat intelligence briefings.

> **Scope.** This is a detector and triage platform performing **static analysis only**. It executes no arbitrary bytecode, runs no emulator instrumentation, and contains no capabilities to generate, alter, or evade malware detection.

---

## Architectural Overview

APKGuard is built as a self-contained, full-stack TypeScript application designed for high-concurrency enterprise triage:

- **Analysis Engine (`src/analyzer.ts`)**: Direct APK container parsing, Dalvik bytecode inspection (`classes.dex`), and `AndroidManifest.xml` attribute extraction via raw binary and ZIP stream decompilation.
- **Threat Vector Attribution**: Evaluates declared permissions, accessibility service bindings (`BIND_ACCESSIBILITY_SERVICE`), SMS reception hooks, overlay capabilities (`SYSTEM_ALERT_WINDOW`), reflection patterns, and hardcoded C2 network indicators against the Drebin Android malware feature taxonomy.
- **AI Threat Intelligence**: Generates executive CISO briefings, plain-English incident advisories, and risk playbooks powered by the Google GenAI SDK.
- **Backend API (`server.ts`)**: Express-powered service with disk-streamed file ingestion (ZIP-bomb mitigation), magic-byte container validation, sliding-window rate limiting, and asynchronous job execution.
- **Analyst Dashboard (`src/`)**: Modern React 19 interface with real-time pipeline telemetry, interactive SVG risk gauges, Drebin feature attribution visualizers, and specimen inspection.

---

## Threat Scoring & Feature Attribution

### 1. Deterministic Multi-Vector Scoring
Scoring is calculated deterministically from extracted bytecode signals without relying on unpredictable black-box hallucinations. The composite risk score (0–100) integrates two key layers:

1. **Manifest & Permission Capabilities (Drebin Taxonomy)**:
   - Accessibility service abuse (`BIND_ACCESSIBILITY_SERVICE`, `AccessibilityEvent` handling)
   - Two-factor SMS harvesting (`READ_SMS`, `RECEIVE_SMS`, `sendTextMessage`)
   - Deceptive screen overlays (`SYSTEM_ALERT_WINDOW`, `TYPE_APPLICATION_OVERLAY`)
   - Persistent autostart (`RECEIVE_BOOT_COMPLETED`)
   - Device surveillance (`READ_PHONE_STATE`, `READ_CALL_LOG`, `READ_CONTACTS`, `CAMERA`)

2. **Bytecode & Network Indicators**:
   - Hardcoded IP addresses and direct socket connections bypassing DNS resolution
   - High-risk Dalvik API calls (`DexClassLoader`, `getRuntime().exec`, `addJavascriptInterface`)
   - Cryptographic obscuration and high bytecode string entropy
   - Ratio of native library binaries (`.so`) to Dalvik executables

### 2. Triage Categorization
- **CRITICAL THREAT (Score ≥ 80)**: Active banking trojan or credential harvester exhibiting overlay or SMS interception capabilities. Immediate enterprise block recommended.
- **HIGH RISK (Score 60–79)**: Suspicious utility or potential dropper requesting unauthorized overlay or background persistence privileges.
- **SUSPICIOUS (Score 40–59)**: Anomalous permission profile or obfuscated bytecode requiring secondary analyst verification.
- **LOW RISK / BENIGN (Score < 40)**: Minimal permission footprint conforming to standard utility or banking application profiles.

---

## Defenses & Security Model

1. **ZIP-Bomb & Memory Exhaustion Protection**: File uploads are buffered to temporary disk storage via `multer.diskStorage` and audited against maximum size limits before buffer reading, preventing heap exhaustion from deeply compressed archives.
2. **Strict Magic-Byte Validation**: File extensions are treated purely as untrusted metadata. Binary contents must strictly match the ZIP container magic header (`PK\x03\x04` / `0x50 0x4B 0x03 0x04`).
3. **Prompt Injection Hardening**: All untrusted data extracted from candidate APKs (package names, discovered URLs, decompiled strings) passes through `sanitizeForPrompt` to strip delimiter escapes, system instructions, and injection payloads before passing to the GenAI model.
4. **Deterministic Score Decoupling**: Numerical risk scores and categorization are computed in TypeScript before GenAI invocation. The LLM cannot alter the calculated threat score.
5. **Path Traversal Immunity**: Report lookups and artifact management validate clean package identifiers and strip relative directory tokens (`..`).

---

## Project Structure

```
APKGuard/
├── server.ts                       Express server: upload streaming, rate limiting & API routes
├── src/
│   ├── analyzer.ts                 Static extraction engine, Drebin vector attribution & GenAI logic
│   ├── types/
│   │   └── index.ts                TypeScript interfaces for reports, manifests, jobs & metrics
│   ├── lib/
│   │   ├── api.ts                  Front-end API client with single-query reports fetching
│   │   ├── store.ts                Zustand state store with SSR-safe persistence
│   │   └── mockData.ts             Pre-seeded specimen dossiers (Banking Trojan, Torch, Calculator)
│   ├── components/
│   │   ├── dashboard/              Scan history, statistics, specimen cards, file upload
│   │   ├── layout/                 Navbar with health monitoring, footer, breadcrumbs
│   │   └── ui/                     RiskGauge, Badge, Toast notifications, Modal dialogs
│   └── pages/
│       ├── LandingPage.tsx         Platform overview, feature architecture, specimen selector
│       ├── DashboardPage.tsx       Active threat overview, triage queues & historical scans
│       ├── AnalysisPage.tsx        Live static analysis pipeline execution & telemetry
│       └── ReportDetailPage.tsx    Full threat dossier: CISO briefing, Drebin vectors & manifest
├── package.json                    Dependencies & build scripts
├── vite.config.ts                  Vite bundler configuration
└── metadata.json                   Platform metadata
```

---

## Getting Started

### Prerequisites
- Node.js 18.x or higher
- npm 9.x or higher
- Gemini API Key (`GEMINI_API_KEY`) for AI Threat Intelligence (optional; falls back to offline analysis if omitted)

### Installation
```bash
# Clone the repository
git clone https://github.com/your-org/apkguard.git
cd apkguard

# Install dependencies
npm install
```

### Environment Configuration
Create a `.env` file in the project root:
```env
PORT=3000
GEMINI_API_KEY=your_gemini_api_key_here
```

### Development Server
```bash
npm run dev
```
The server will start at `http://localhost:3000` with the API and Vite dev middleware integrated.

### Production Build
```bash
npm run build
npm run start
```

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Service health status and engine readiness |
| `GET` | `/stats` | Aggregate system metrics (scans, threats, severity breakdown) |
| `GET` | `/reports` | Complete list of all analyzed APK threat reports |
| `GET` | `/report/:apk_name` | Full threat dossier for a specific APK specimen |
| `DELETE` | `/report/:apk_name` | Remove a threat report from memory |
| `POST` | `/analyse` | Upload `.apk` binary for full static analysis and GenAI briefing |
| `POST` | `/quick-score` | Upload `.apk` binary for fast static feature scoring (skips GenAI) |
| `GET` | `/job/:job_id` | Check status, progress, and telemetry logs for a running analysis job |
| `POST` | `/job/:job_id/cancel` | Abort a running pipeline execution |

---

## Author & Acknowledgements

**APKGuard Engineering Team**
Built for high-assurance mobile threat triage and banking fraud defense.
Licensed under the [MIT License](LICENSE).
