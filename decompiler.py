"""
APKGuard - Module 1: APK Decompilation Pipeline
Runs APKTool (resources/manifest) + JADX (Java source) on any APK
and organises the output into a structured folder.
"""

import subprocess
import os
import sys
import json
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime

# ── Configuration ────────────────────────────────────────────────────────────
BASE_DIR      = Path("C:/APKGuard")
TOOLS_DIR     = BASE_DIR / "tools"
UPLOADS_DIR   = BASE_DIR / "uploads"
OUTPUT_DIR    = BASE_DIR / "output"

APKTOOL_PATH  = TOOLS_DIR / "apktool.bat"
JADX_PATH     = TOOLS_DIR / "jadx" / "bin" / "jadx.bat"

# ── Helpers ──────────────────────────────────────────────────────────────────

def log(msg: str, level: str = "INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    icons = {"INFO": "•", "OK": "✓", "ERR": "✗", "WARN": "!"}
    print(f"[{ts}] {icons.get(level,'•')} {msg}")


def run(cmd: list[str], label: str) -> tuple[bool, str]:
    """Run a subprocess, stream output, return (success, stdout)."""
    log(f"Running {label}...")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300          # 5-minute timeout per tool
        )
        if result.returncode in (0, 1):
            log(f"{label} completed successfully", "OK")
            return True, result.stdout
        else:
            log(f"{label} failed (exit {result.returncode})", "ERR")
            log(result.stderr[:500], "ERR")
            return False, result.stderr
    except subprocess.TimeoutExpired:
        log(f"{label} timed out after 5 minutes", "ERR")
        return False, "timeout"
    except FileNotFoundError as e:
        log(f"Tool not found: {e}", "ERR")
        return False, str(e)


# ── Core decompilation steps ─────────────────────────────────────────────────

def run_apktool(apk_path: Path, out_dir: Path) -> bool:
    """
    APKTool: decodes resources, AndroidManifest.xml, and Smali bytecode.
    Output → out_dir/apktool/
    """
    dest = out_dir / "apktool"
    if dest.exists():
        shutil.rmtree(dest)

    cmd = [
        str(APKTOOL_PATH),
        "d",                    # decode
        str(apk_path),
        "-o", str(dest),
        "-f",                   # force overwrite
        "--no-src",             # we get source from JADX; keep smali only
    ]
    ok, _ = run(cmd, "APKTool")
    return ok


def run_jadx(apk_path: Path, out_dir: Path) -> bool:
    """
    JADX: decompiles Dalvik bytecode → readable Java source.
    Output → out_dir/jadx/
    """
    dest = out_dir / "jadx"
    if dest.exists():
        shutil.rmtree(dest)

    cmd = [
        str(JADX_PATH),
        str(apk_path),
        "-d", str(dest),        # output directory
        "--show-bad-code",      # include partially decompiled code
        "--no-res",             # resources already handled by APKTool
        "--threads-count", "4",
    ]
    ok, _ = run(cmd, "JADX")
    return ok


# ── Feature extraction from decompiled output ────────────────────────────────

def parse_manifest(apktool_dir: Path) -> dict:
    """Extract key fields from AndroidManifest.xml."""
    manifest_path = apktool_dir / "AndroidManifest.xml"
    if not manifest_path.exists():
        log("AndroidManifest.xml not found", "WARN")
        return {}

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        ns = "http://schemas.android.com/apk/res/android"

        # Package name & version
        package     = root.attrib.get("package", "unknown")
        version     = root.attrib.get(f"{{{ns}}}versionName", "unknown")
        version_code= root.attrib.get(f"{{{ns}}}versionCode", "unknown")

        # Permissions
        permissions = [
            elem.attrib.get(f"{{{ns}}}name", "")
            for elem in root.iter("uses-permission")
        ]

        # Activities, Services, Receivers, Providers
        activities  = [e.attrib.get(f"{{{ns}}}name","") for e in root.iter("activity")]
        services    = [e.attrib.get(f"{{{ns}}}name","") for e in root.iter("service")]
        receivers   = [e.attrib.get(f"{{{ns}}}name","") for e in root.iter("receiver")]
        providers   = [e.attrib.get(f"{{{ns}}}name","") for e in root.iter("provider")]

        # Dangerous permission flags
        DANGEROUS_PERMS = {
            "READ_SMS", "SEND_SMS", "RECEIVE_SMS",
            "READ_CONTACTS", "READ_CALL_LOG",
            "RECORD_AUDIO", "CAMERA",
            "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
            "READ_PHONE_STATE", "PROCESS_OUTGOING_CALLS",
            "BIND_ACCESSIBILITY_SERVICE",
            "SYSTEM_ALERT_WINDOW", "RECEIVE_BOOT_COMPLETED",
            "REQUEST_INSTALL_PACKAGES",
        }
        dangerous_found = [
            p.split(".")[-1] for p in permissions
            if p.split(".")[-1] in DANGEROUS_PERMS
        ]

        return {
            "package":          package,
            "version_name":     version,
            "version_code":     version_code,
            "permissions":      permissions,
            "dangerous_permissions": dangerous_found,
            "activities_count": len(activities),
            "services_count":   len(services),
            "receivers_count":  len(receivers),
            "providers_count":  len(providers),
            "activities":       activities[:20],   # cap list length
            "services":         services[:20],
            "receivers":        receivers[:20],
        }

    except ET.ParseError as e:
        log(f"Failed to parse manifest: {e}", "ERR")
        return {}


def extract_strings_and_urls(jadx_dir: Path) -> dict:
    """
    Scan all decompiled Java files for:
    - Hardcoded URLs / IPs
    - Suspicious keywords (shell commands, crypto, overlay, etc.)
    - Obfuscation indicators (very short class/method names)
    """
    import re

    url_pattern  = re.compile(r'https?://[^\s\'"<>]{6,}')
    ip_pattern   = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    SUSPICIOUS_KEYWORDS = [
        "getRuntime", "exec(", "ProcessBuilder",
        "Cipher", "AES", "DES", "Base64",
        "AccessibilityService", "onAccessibilityEvent",
        "BIND_DEVICE_ADMIN", "DevicePolicyManager",
        "HttpURLConnection", "OkHttpClient",
        "sendTextMessage", "getSubscriberId",
        "getDeviceId", "getLine1Number",
        "PackageInstaller", "requestInstallPackages",
        "KeyLogger", "clipboard", "getClipboard",
        "overlay", "SYSTEM_ALERT_WINDOW",
        "WebView", "loadUrl", "addJavascriptInterface",
    ]

    urls             = set()
    ips              = set()
    suspicious_hits  = {}
    total_java_files = 0
    obfuscation_score= 0

    java_root = jadx_dir / "sources"
    if not java_root.exists():
        java_root = jadx_dir   # fallback

    for java_file in java_root.rglob("*.java"):
        total_java_files += 1
        try:
            content = java_file.read_text(encoding="utf-8", errors="ignore")

            # URLs and IPs
            urls.update(url_pattern.findall(content))
            ips.update(ip_pattern.findall(content))

            # Suspicious keyword scan
            for kw in SUSPICIOUS_KEYWORDS:
                if kw in content:
                    suspicious_hits[kw] = suspicious_hits.get(kw, 0) + 1

            # Obfuscation: very short class names (a.java, b.java, etc.)
            if len(java_file.stem) <= 2:
                obfuscation_score += 1

        except Exception:
            pass

    return {
        "total_java_files":   total_java_files,
        "hardcoded_urls":     list(urls)[:30],
        "hardcoded_ips":      list(ips)[:20],
        "suspicious_keywords":suspicious_hits,
        "obfuscation_score":  obfuscation_score,
        "obfuscation_flag":   obfuscation_score > (total_java_files * 0.3) if total_java_files else False,
    }


def count_smali_files(apktool_dir: Path) -> dict:
    """Count smali files and detect native libraries."""
    smali_files = list(apktool_dir.rglob("*.smali"))
    so_files    = list(apktool_dir.rglob("*.so"))
    dex_count   = len(list(apktool_dir.rglob("*.dex")))

    return {
        "smali_file_count": len(smali_files),
        "native_libs":      [f.name for f in so_files],
        "native_lib_count": len(so_files),
        "dex_count":        dex_count,
    }


# ── Risk pre-score (heuristic, before ML) ────────────────────────────────────

DANGEROUS_PERM_WEIGHTS = {
    "READ_SMS": 15, "SEND_SMS": 15, "RECEIVE_SMS": 12,
    "BIND_ACCESSIBILITY_SERVICE": 20,
    "SYSTEM_ALERT_WINDOW": 18,
    "REQUEST_INSTALL_PACKAGES": 18,
    "READ_CONTACTS": 8, "READ_CALL_LOG": 8,
    "RECORD_AUDIO": 10, "CAMERA": 8,
    "ACCESS_FINE_LOCATION": 7,
    "READ_PHONE_STATE": 7, "PROCESS_OUTGOING_CALLS": 10,
}

SUSPICIOUS_KW_WEIGHTS = {
    "AccessibilityService": 15, "onAccessibilityEvent": 15,
    "BIND_DEVICE_ADMIN": 18, "DevicePolicyManager": 18,
    "getRuntime": 10, "exec(": 12, "ProcessBuilder": 12,
    "sendTextMessage": 12, "getSubscriberId": 8,
    "KeyLogger": 20, "addJavascriptInterface": 10,
    "requestInstallPackages": 15,
}

def compute_heuristic_score(manifest: dict, strings: dict) -> dict:
    score = 0
    reasons = []

    # Dangerous permissions
    for perm in manifest.get("dangerous_permissions", []):
        w = DANGEROUS_PERM_WEIGHTS.get(perm, 5)
        score += w
        reasons.append(f"Dangerous permission: {perm} (+{w})")

    # Suspicious keywords
    for kw, count in strings.get("suspicious_keywords", {}).items():
        w = SUSPICIOUS_KW_WEIGHTS.get(kw, 3)
        score += w
        reasons.append(f"Suspicious code: {kw} found in {count} file(s) (+{w})")

    # Obfuscation
    if strings.get("obfuscation_flag"):
        score += 20
        reasons.append("Heavy obfuscation detected (+20)")

    # Hardcoded IPs (unusual for legit apps)
    ip_count = len(strings.get("hardcoded_ips", []))
    if ip_count > 3:
        score += 10
        reasons.append(f"Hardcoded IP addresses found: {ip_count} (+10)")

    # Many receivers (common in spyware/adware)
    if manifest.get("receivers_count", 0) > 5:
        score += 8
        reasons.append(f"High receiver count: {manifest['receivers_count']} (+8)")

    # Cap at 100
    score = min(score, 100)

    if score >= 70:   category = "CRITICAL THREAT"
    elif score >= 50: category = "HIGH RISK"
    elif score >= 30: category = "SUSPICIOUS"
    else:             category = "LOW RISK"

    return {
        "heuristic_score": score,
        "category":        category,
        "reasons":         reasons,
    }


# ── Main pipeline ─────────────────────────────────────────────────────────────

def analyse_apk(apk_path: str) -> dict:
    apk = Path(apk_path)

    if not apk.exists():
        log(f"APK not found: {apk_path}", "ERR")
        sys.exit(1)

    log(f"Starting analysis: {apk.name}")
    log("=" * 55)

    # Create output directory named after APK (without extension)
    out_dir = OUTPUT_DIR / apk.stem
    out_dir.mkdir(parents=True, exist_ok=True)

    results = {
        "apk_name":  apk.name,
        "apk_size_kb": round(apk.stat().st_size / 1024, 1),
        "analysed_at": datetime.now().isoformat(),
    }

    # ── Step 1: APKTool ──────────────────────────────────────
    apktool_ok = run_apktool(apk, out_dir)
    results["apktool_success"] = apktool_ok

    # ── Step 2: JADX ────────────────────────────────────────
    jadx_ok = run_jadx(apk, out_dir)
    results["jadx_success"] = jadx_ok

    # ── Step 3: Parse manifest ───────────────────────────────
    if apktool_ok:
        log("Parsing AndroidManifest.xml...")
        manifest = parse_manifest(out_dir / "apktool")
        results["manifest"] = manifest
        log(f"Package: {manifest.get('package','?')}", "OK")
        log(f"Dangerous permissions: {manifest.get('dangerous_permissions', [])}", "OK")

    # ── Step 4: Scan Java source ─────────────────────────────
    if jadx_ok:
        log("Scanning decompiled Java source...")
        strings = extract_strings_and_urls(out_dir / "jadx")
        results["static_analysis"] = strings
        log(f"Java files scanned: {strings['total_java_files']}", "OK")
        log(f"Suspicious keywords: {list(strings['suspicious_keywords'].keys())}", "OK")
        log(f"Obfuscation flag: {strings['obfuscation_flag']}", "OK")

    # ── Step 5: Smali / native lib stats ────────────────────
    if apktool_ok:
        smali = count_smali_files(out_dir / "apktool")
        results["smali_stats"] = smali
        log(f"Smali files: {smali['smali_file_count']}, Native libs: {smali['native_lib_count']}", "OK")

    # ── Step 6: Heuristic pre-score ─────────────────────────
    manifest = results.get("manifest", {})
    strings  = results.get("static_analysis", {})
    scoring  = compute_heuristic_score(manifest, strings)
    results["heuristic_scoring"] = scoring

    log("=" * 55)
    log(f"HEURISTIC RISK SCORE : {scoring['heuristic_score']} / 100")
    log(f"CATEGORY             : {scoring['category']}")
    log("Top risk reasons:")
    for r in scoring["reasons"][:5]:
        log(f"  {r}")

    # ── Save JSON report ─────────────────────────────────────
    report_path = out_dir / "report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    log(f"Full report saved → {report_path}", "OK")

    return results


# ── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("\nUsage:  python decompiler.py <path_to_apk>")
        print("Example: python decompiler.py C:\\APKGuard\\uploads\\sample.apk\n")
        sys.exit(1)

    analyse_apk(sys.argv[1])