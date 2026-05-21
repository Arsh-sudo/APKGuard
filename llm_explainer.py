"""
APKGuard - Module 3: LLM Explanation Layer
Uses Ollama (Llama 3.2 local) to analyse decompiled Java code and
generate human-readable threat explanations for bank security teams.
"""

import json
import sys
import re
import requests
from pathlib import Path
from datetime import datetime

# ── Configuration ─────────────────────────────────────────────────────────────
BASE_DIR       = Path("C:/APKGuard")
OUTPUT_DIR     = BASE_DIR / "output"
OLLAMA_URL     = "http://localhost:11434/api/generate"
OLLAMA_MODEL   = "llama3.2"
MAX_CODE_CHARS = 6000   # chars of code to send per LLM call (context limit)

# ── Logging ───────────────────────────────────────────────────────────────────
def log(msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    icons = {"INFO": "•", "OK": "✓", "ERR": "✗", "WARN": "!"}
    print(f"[{ts}] {icons.get(level,'•')} {msg}")


# ── Ollama helper ─────────────────────────────────────────────────────────────

def ollama_generate(prompt: str, system: str = "") -> str:
    """Send a prompt to local Ollama and return the response text."""
    payload = {
        "model":  OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,      # low temp = consistent, factual output
            "num_predict": 800,      # max tokens in response
        }
    }
    if system:
        payload["system"] = system

    try:
        resp = requests.post(OLLAMA_URL, json=payload, timeout=180)
        resp.raise_for_status()
        return resp.json().get("response", "").strip()
    except requests.exceptions.ConnectionError:
        log("Ollama is not running! Start it with: ollama serve", "ERR")
        sys.exit(1)
    except requests.exceptions.Timeout:
        log("Ollama timed out after 120s", "ERR")
        return "Analysis timed out."
    except Exception as e:
        log(f"Ollama error: {e}", "ERR")
        return f"Error: {e}"


# ── Code sampling ─────────────────────────────────────────────────────────────

def sample_suspicious_code(apk_name: str, keywords: list[str]) -> str:
    """
    Find Java files containing suspicious keywords and extract
    the most relevant code snippets for LLM analysis.
    """
    jadx_dir = OUTPUT_DIR / apk_name / "jadx"
    if not jadx_dir.exists():
        return "No decompiled source available."

    snippets = []
    found_files = 0

    # Priority: search for most dangerous keywords first
    priority_keywords = [
        "AccessibilityService", "BIND_DEVICE_ADMIN", "sendTextMessage",
        "getRuntime", "exec(", "ProcessBuilder", "KeyLogger",
        "addJavascriptInterface", "requestInstallPackages",
        "getSubscriberId", "getDeviceId", "Cipher", "Base64"
    ]
    search_order = [k for k in priority_keywords if k in keywords] + \
                   [k for k in keywords if k not in priority_keywords]

    java_root = jadx_dir / "sources"
    if not java_root.exists():
        java_root = jadx_dir

    for keyword in search_order:
        if len("\n".join(snippets)) > MAX_CODE_CHARS:
            break
        for java_file in java_root.rglob("*.java"):
            try:
                content = java_file.read_text(encoding="utf-8", errors="ignore")
                if keyword in content:
                    # Extract lines around the keyword hit
                    lines = content.splitlines()
                    for i, line in enumerate(lines):
                        if keyword in line:
                            start = max(0, i - 3)
                            end   = min(len(lines), i + 8)
                            chunk = "\n".join(lines[start:end])
                            header = f"// File: {java_file.name} (keyword: {keyword})"
                            snippets.append(f"{header}\n{chunk}")
                            found_files += 1
                            break   # one snippet per file per keyword
            except Exception:
                pass
        if found_files >= 8:
            break

    if not snippets:
        return "No suspicious code snippets found."

    return "\n\n" + "─" * 40 + "\n\n".join(snippets[:8])


# ── LLM Analysis tasks ────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a senior Android malware analyst working for a bank's 
cybersecurity team. You analyse decompiled Android app code and permission patterns 
to detect threats. Be precise, professional, and concise. Focus on what is 
actionable for a bank security officer. Avoid unnecessary disclaimers."""


def analyse_permissions(dangerous_perms: list[str], package: str) -> str:
    """Ask LLM to explain what the dangerous permissions mean in context."""
    if not dangerous_perms:
        prompt = f"""The Android app '{package}' requests NO dangerous permissions.
In 2-3 sentences, explain what this means for a banking app from a security perspective."""
    else:
        perms_str = "\n".join(f"- {p}" for p in dangerous_perms)
        prompt = f"""The Android app '{package}' requests these dangerous permissions:
{perms_str}

For each permission, briefly explain:
1. What data/capability it accesses
2. How malware typically abuses it to steal banking credentials or commit fraud

Be concise — 1-2 sentences per permission. Use a numbered list."""

    log("LLM analysing permissions...")
    return ollama_generate(prompt, SYSTEM_PROMPT)


def analyse_code_snippets(code: str, keywords: list[str], package: str) -> str:
    """Ask LLM to analyse the actual decompiled code for malicious patterns."""
    keywords_str = ", ".join(keywords[:10])
    prompt = f"""Analyse these decompiled Java code snippets from the Android app '{package}'.
Suspicious keywords detected: {keywords_str}

CODE SNIPPETS:
{code[:MAX_CODE_CHARS]}

Tasks:
1. Identify the most concerning code patterns and explain what they do
2. Determine if this looks like legitimate app code or malicious behaviour
3. If malicious, describe the attack type (e.g. credential theft, SMS fraud, overlay attack)

Be specific about line-level evidence. Keep your response under 300 words."""

    log("LLM analysing decompiled code snippets...")
    return ollama_generate(prompt, SYSTEM_PROMPT)


def generate_threat_summary(
    package: str,
    final_score: float,
    category: str,
    dangerous_perms: list[str],
    keywords: list[str],
    perm_analysis: str,
    code_analysis: str,
) -> str:
    """Generate a concise executive threat summary for the bank security team."""
    prompt = f"""Write a professional threat intelligence summary for a bank CISO.

APP DETAILS:
- Package: {package}
- Risk Score: {final_score}/100
- Category: {category}
- Dangerous Permissions: {', '.join(dangerous_perms) if dangerous_perms else 'None'}
- Suspicious Code Patterns: {', '.join(keywords[:8]) if keywords else 'None'}

PERMISSION ANALYSIS:
{perm_analysis[:500]}

CODE ANALYSIS:
{code_analysis[:500]}

Write a structured summary with these exact sections:
VERDICT: (one sentence — safe/suspicious/malicious and why)
THREAT TYPE: (e.g. Banking Trojan, Spyware, Adware, Legitimate App)
KEY RISKS: (3 bullet points max)
RECOMMENDED ACTION: (one of: Block immediately / Monitor / Allow with caution / Safe to allow)

Keep total response under 200 words. Be direct and professional."""

    log("LLM generating executive threat summary...")
    return ollama_generate(prompt, SYSTEM_PROMPT)


def generate_plain_english_explanation(
    package: str, final_score: float, category: str,
    perm_analysis: str, code_analysis: str
) -> str:
    """Generate a plain-English explanation for non-technical bank staff."""
    prompt = f"""Explain in plain English (no jargon) what this Android app does and 
whether it is dangerous. Write as if explaining to a bank branch manager, not a 
technical person.

App: {package}
Risk Score: {final_score}/100 ({category})

Technical findings:
{perm_analysis[:400]}
{code_analysis[:400]}

Keep it under 100 words. Start with 'This app...'"""

    log("LLM generating plain-English explanation...")
    return ollama_generate(prompt, SYSTEM_PROMPT)


# ── Main analysis pipeline ────────────────────────────────────────────────────

def explain_apk(apk_name: str):
    """
    Full LLM explanation pipeline for a decompiled + scored APK.
    Reads report.json (written by Modules 1 & 2) and adds LLM analysis.
    """
    report_path = OUTPUT_DIR / apk_name / "report.json"
    if not report_path.exists():
        log(f"Report not found: {report_path}", "ERR")
        log("Run decompiler.py and classifier.py first!", "ERR")
        sys.exit(1)

    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    # ── Extract data from previous modules ───────────────────────
    package         = report.get("manifest", {}).get("package", apk_name)
    dangerous_perms = report.get("manifest", {}).get("dangerous_permissions", [])
    keywords        = list(report.get("static_analysis", {})
                               .get("suspicious_keywords", {}).keys())
    ml_data         = report.get("ml_scoring", {})
    final_score     = ml_data.get("final_score",
                      report.get("heuristic_scoring", {}).get("heuristic_score", 0))
    category        = ml_data.get("category",
                      report.get("heuristic_scoring", {}).get("category", "UNKNOWN"))

    log("=" * 55)
    log(f"Starting LLM analysis for: {package}")
    log(f"Risk Score: {final_score}/100  |  Category: {category}")
    log("=" * 55)

    # ── Check Ollama is running ───────────────────────────────────
    try:
        ping = requests.get("http://localhost:11434", timeout=5)
        log("Ollama is running", "OK")
    except Exception:
        log("Ollama is not running! Open a new terminal and run: ollama serve", "ERR")
        sys.exit(1)

    # ── Run LLM analyses ──────────────────────────────────────────

    # 1. Permission analysis
    perm_analysis = analyse_permissions(dangerous_perms, package)
    log("Permission analysis done", "OK")

    # 2. Code snippet analysis
    code_snippets = sample_suspicious_code(apk_name, keywords)
    code_analysis = analyse_code_snippets(code_snippets, keywords, package)
    log("Code analysis done", "OK")

    # 3. Executive threat summary
    threat_summary = generate_threat_summary(
        package, final_score, category,
        dangerous_perms, keywords,
        perm_analysis, code_analysis
    )
    log("Threat summary done", "OK")

    # 4. Plain-English explanation
    plain_explanation = generate_plain_english_explanation(
        package, final_score, category,
        perm_analysis, code_analysis
    )
    log("Plain-English explanation done", "OK")

    # ── Print full analysis ───────────────────────────────────────
    print("\n" + "═" * 55)
    print("  APKGuard — LLM Threat Intelligence Report")
    print("═" * 55)
    print(f"\n📦 App     : {package}")
    print(f"🎯 Score   : {final_score}/100  |  {category}\n")

    print("─" * 55)
    print("1. PERMISSION ANALYSIS")
    print("─" * 55)
    print(perm_analysis)

    print("\n" + "─" * 55)
    print("2. CODE BEHAVIOUR ANALYSIS")
    print("─" * 55)
    print(code_analysis)

    print("\n" + "─" * 55)
    print("3. EXECUTIVE THREAT SUMMARY")
    print("─" * 55)
    print(threat_summary)

    print("\n" + "─" * 55)
    print("4. PLAIN ENGLISH (for non-technical staff)")
    print("─" * 55)
    print(plain_explanation)
    print("\n" + "═" * 55)

    # ── Save to report.json ───────────────────────────────────────
    report["llm_analysis"] = {
        "model":               OLLAMA_MODEL,
        "permission_analysis": perm_analysis,
        "code_analysis":       code_analysis,
        "threat_summary":      threat_summary,
        "plain_explanation":   plain_explanation,
    }

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    log(f"\nFull report updated → {report_path}", "OK")
    return report["llm_analysis"]


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("\nUsage:  python llm_explainer.py <apk_name>")
        print("Example: python llm_explainer.py Calculator\n")
        sys.exit(1)

    explain_apk(sys.argv[1])
