# APKGuard 🛡️
### GenAI-Powered Banking APK Threat Intelligence Platform

> PSB Cybersecurity, Fraud & AI Hackathon 2026 | Bank of India & IIT Hyderabad

APKGuard automatically reverse-engineers suspicious Android APKs, performs static and dynamic analysis, and generates a calibrated Fraud Risk Score (0–100) using a combination of ML classification and LLM-powered threat explanations.

---

## 🚀 Quick Start (Docker)

```bash
# Clone / download the project
cd APKGuard

# Start everything with one command
docker-compose up --build

# Open the dashboard
# http://localhost:3000
```

---

## 🏗️ Architecture

```
APK File
   │
   ▼
┌─────────────────────────────────────────┐
│  Layer 1 — Reverse Engineering          │
│  APKTool → Manifest, Smali, Resources   │
│  JADX    → Decompiled Java Source       │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│  Layer 2 — Static Analysis              │
│  • 80+ feature extraction               │
│  • Dangerous permission detection       │
│  • Suspicious keyword scanning          │
│  • Obfuscation detection                │
│  • Hardcoded URL/IP extraction          │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│  Layer 3 — GenAI Risk Scoring           │
│  • XGBoost ML classifier (92.5% acc)   │
│  • Trained on Drebin dataset            │
│  • Ollama LLM (Llama 3.2) explanation  │
│  • Final Fraud Risk Score (0–100)       │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│  FastAPI Backend + React Dashboard      │
│  • Real-time progress tracking          │
│  • Threat report with 4 analysis tabs  │
│  • Scan history & statistics            │
└─────────────────────────────────────────┘
```

---

## 📊 Results

| APK | ML Score | Final Score | Category |
|-----|----------|-------------|----------|
| Google Calculator (legit) | 1.1/100 | 27.5/100 | ✅ LOW RISK |
| Banking Trojan (malware) | 99.8/100 | 99.9/100 | 🔴 CRITICAL THREAT |

---

## 🔧 Manual Setup (Without Docker)

### Prerequisites
- Python 3.11+
- Java 11+
- Node.js 18+
- Ollama

### Backend
```bash
cd APKGuard
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt

# Train ML model
python classifier.py train

# Start API
python api.py
```

### Frontend
```bash
cd dashboard
npm install
npm start
```

### LLM (optional)
```bash
ollama pull llama3.2
# Ollama runs automatically on port 11434
```

---

## 📁 Project Structure

```
APKGuard/
├── decompiler.py       # Module 1: APK decompilation pipeline
├── classifier.py       # Module 2: XGBoost ML classifier
├── llm_explainer.py    # Module 3: Ollama LLM explanation
├── api.py              # Module 4: FastAPI REST backend
├── dashboard/          # Module 5: React frontend
├── tools/
│   ├── apktool.bat     # APKTool decompiler
│   ├── apktool.jar
│   └── jadx/           # JADX Java decompiler
├── models/
│   ├── apkguard_xgb.pkl        # Trained XGBoost model
│   └── feature_columns.pkl     # Feature column list
├── data/
│   └── drebin.csv      # Drebin malware dataset
├── uploads/            # APK files for analysis
├── output/             # Analysis reports (JSON)
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## 🧠 Datasets Used

| Dataset | Description | Size |
|---------|-------------|------|
| Drebin | Labelled Android malware features | ~400 samples |
| AndroZoo | Large-scale APK repository | Reference |
| VirusTotal API | Multi-engine AV validation | Live API |
| CERT-In Alerts | Govt cyber-fraud feeds | Public |

---

## 🏆 Key Innovations

1. **LLM Code Explainability** — GenAI explains WHY an APK is malicious in plain English
2. **Zero-Shot Threat Detection** — LLM catches novel obfuscated malware
3. **Banking-Specific Profiles** — Baseline from legitimate Indian banking apps
4. **Real-Time CERT-In Integration** — Cross-references government cyber-fraud alerts
5. **Bank-Ready Threat Report** — One-click PDF for CISO review

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/analyse` | Upload APK for full analysis (with LLM) |
| POST | `/quick-score` | Upload APK for fast ML-only score |
| GET | `/job/{job_id}` | Poll analysis progress |
| GET | `/reports` | List all analysed APKs |
| GET | `/report/{apk_name}` | Get full report |
| GET | `/stats` | Dashboard statistics |
| DELETE | `/report/{apk_name}` | Delete a report |

Interactive API docs: **http://localhost:8000/docs**

---

## 👥 Team

Built for PSB Cybersecurity, Fraud & AI Hackathon 2026
Bank of India × IIT Hyderabad
