"""
APKGuard - Module 2: ML Risk Classifier
Trains an XGBoost classifier on the Drebin dataset and scores APKs
using features extracted by Module 1 (decompiler.py).
"""

import json
import os
import sys
import pickle
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime

# ── Configuration ─────────────────────────────────────────────────────────────
BASE_DIR    = Path(os.getenv("APKGUARD_HOME", Path(__file__).resolve().parent))
DATA_DIR    = BASE_DIR / "data"
MODELS_DIR  = BASE_DIR / "models"
OUTPUT_DIR  = BASE_DIR / "output"

DREBIN_CSV  = DATA_DIR / "drebin.csv"
MODEL_FILE  = MODELS_DIR / "apkguard_xgb.pkl"
FEATURES_FILE = MODELS_DIR / "feature_columns.pkl"

MODELS_DIR.mkdir(parents=True, exist_ok=True)

# ── Logging ───────────────────────────────────────────────────────────────────
def log(msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    icons = {"INFO": "•", "OK": "✓", "ERR": "✗", "WARN": "!"}
    print(f"[{ts}] {icons.get(level,'•')} {msg}")


# ── Step 1: Load & parse Drebin CSV ──────────────────────────────────────────

def load_drebin() -> tuple[pd.DataFrame, pd.Series]:
    """
    The Drebin CSV uses semicolons as separators and has all permission
    columns as binary (0/1) features. Last column is 'type' (S=malware, B=benign).
    """
    log("Loading Drebin dataset...")

    # Read with semicolon separator
    df = pd.read_csv(DREBIN_CSV, sep=";")

    log(f"Raw shape: {df.shape}", "OK")
    log(f"Columns (last 3): {df.columns.tolist()[-3:]}", "OK")

    # The label column is named 'type'
    if "type" not in df.columns:
        # Fallback: last column is label
        label_col = df.columns[-1]
        log(f"'type' column not found, using last column: {label_col}", "WARN")
    else:
        label_col = "type"

    # Show label distribution
    log(f"Label values: {df[label_col].unique().tolist()}", "OK")
    log(f"Label counts:\n{df[label_col].value_counts().to_string()}", "OK")

    # Encode labels: S (malware) = 1, B (benign) = 0
    # Handle both string and numeric labels
    unique_labels = df[label_col].unique()
    if set(unique_labels).issubset({"S", "B", "malware", "benign", 0, 1, "0", "1"}):
        label_map = {"S": 1, "B": 0, "malware": 1, "benign": 0, "1": 1, "0": 0, 1: 1, 0: 0}
        y = df[label_col].map(label_map).fillna(df[label_col].astype(int))
    else:
        # If already numeric
        y = df[label_col].astype(int)

    # Features: all columns except label
    X = df.drop(columns=[label_col])

    # Keep only numeric columns (drop any stray string columns)
    X = X.select_dtypes(include=[np.number])

    # Fill any NaN with 0
    X = X.fillna(0)

    log(f"Features shape: {X.shape}", "OK")
    log(f"Malware samples: {int(y.sum())}  Benign samples: {int((y==0).sum())}", "OK")

    return X, y


# ── Step 2: Train XGBoost classifier ─────────────────────────────────────────

def train_model(X: pd.DataFrame, y: pd.Series):
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import (classification_report, confusion_matrix,
                                  roc_auc_score, accuracy_score)
    from xgboost import XGBClassifier

    log("Splitting data (80% train / 20% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    log(f"Train: {len(X_train)} samples  |  Test: {len(X_test)} samples", "OK")

    # XGBoost model — tuned for small dataset
    log("Training XGBoost classifier...")
    model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )

    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=False,
    )
    log("Training complete!", "OK")

    # ── Evaluation ────────────────────────────────────────────────
    y_pred      = model.predict(X_test)
    y_pred_prob = model.predict_proba(X_test)[:, 1]

    accuracy = accuracy_score(y_test, y_pred)
    auc      = roc_auc_score(y_test, y_pred_prob)

    log("=" * 50)
    log(f"ACCURACY : {accuracy*100:.2f}%", "OK")
    log(f"ROC-AUC  : {auc:.4f}", "OK")
    log("Classification Report:")
    print(classification_report(y_test, y_pred,
                                 target_names=["Benign", "Malware"]))

    log("Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"  True Benign  (TN): {cm[0][0]}   False Alarm  (FP): {cm[0][1]}")
    print(f"  Missed Malware(FN):{cm[1][0]}   Caught Malware(TP):{cm[1][1]}")
    log("=" * 50)

    # ── Feature importance (top 20) ───────────────────────────────
    importances = pd.Series(model.feature_importances_, index=X.columns)
    top20 = importances.nlargest(20)
    log("Top 20 most important features:")
    for feat, score in top20.items():
        # Shorten long permission names for display
        short = feat.split(".")[-1] if "." in feat else feat
        print(f"  {short:<45} {score:.4f}")

    return model, accuracy, auc


# ── Step 3: Save model ────────────────────────────────────────────────────────

def save_model(model, feature_columns):
    with open(MODEL_FILE, "wb") as f:
        pickle.dump(model, f)
    with open(FEATURES_FILE, "wb") as f:
        pickle.dump(feature_columns, f)
    log(f"Model saved → {MODEL_FILE}", "OK")
    log(f"Feature list saved → {FEATURES_FILE}", "OK")


# ── Step 4: Load model ────────────────────────────────────────────────────────

def load_model():
    if not MODEL_FILE.exists():
        log("No trained model found. Run: python classifier.py train", "ERR")
        sys.exit(1)
    with open(MODEL_FILE, "rb") as f:
        model = pickle.load(f)
    with open(FEATURES_FILE, "rb") as f:
        feature_columns = pickle.load(f)
    log("Model loaded successfully", "OK")
    return model, feature_columns


# ── Step 5: Score an APK using its report.json ───────────────────────────────

def score_apk(apk_name: str):
    """
    Loads report.json from Module 1 output and scores it with the ML model.
    Combines ML probability with heuristic score for final result.
    """
    report_path = OUTPUT_DIR / apk_name / "report.json"
    if not report_path.exists():
        log(f"Report not found: {report_path}", "ERR")
        log("Run decompiler.py on the APK first!", "ERR")
        sys.exit(1)

    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    model, feature_columns = load_model()

    # Build feature vector from manifest permissions
    permissions = report.get("manifest", {}).get("permissions", [])
    permission_set = set(p.split("android.permission.")[-1]
                         if "android.permission." in p else p
                         for p in permissions)

    # Create feature vector aligned to training columns
    feature_vector = {}
    for col in feature_columns:
        # Match permission name (strip android.permission. prefix)
        col_short = col.split(".")[-1] if "." in col else col
        feature_vector[col] = 1 if col_short in permission_set or col in permission_set else 0

    X_new = pd.DataFrame([feature_vector])[feature_columns].fillna(0)

    # ML prediction
    ml_prob     = model.predict_proba(X_new)[0][1]  # probability of malware
    ml_score    = round(ml_prob * 100, 1)

    # Heuristic score from Module 1
    heuristic   = report.get("heuristic_scoring", {}).get("heuristic_score", 0)

    # Combined final score (60% ML + 40% heuristic)
    final_score = round(0.6 * ml_score + 0.4 * heuristic, 1)
    final_score = min(final_score, 100)

    if final_score >= 70:   category = "CRITICAL THREAT"
    elif final_score >= 50: category = "HIGH RISK"
    elif final_score >= 30: category = "SUSPICIOUS"
    else:                   category = "LOW RISK"

    log("=" * 55)
    log(f"APK              : {report.get('apk_name', apk_name)}")
    log(f"Package          : {report.get('manifest',{}).get('package','unknown')}")
    log(f"ML Score         : {ml_score} / 100  (XGBoost probability)")
    log(f"Heuristic Score  : {heuristic} / 100  (Rule-based)")
    log(f"FINAL SCORE      : {final_score} / 100")
    log(f"CATEGORY         : {category}")
    log("=" * 55)

    # Top risk reasons from heuristic
    reasons = report.get("heuristic_scoring", {}).get("reasons", [])
    if reasons:
        log("Top risk factors:")
        for r in reasons[:5]:
            log(f"  {r}")

    # Update report.json with ML results
    report["ml_scoring"] = {
    	"ml_probability":  float(ml_prob),
    	"ml_score":        float(ml_score),
    	"heuristic_score": float(heuristic),
    	"final_score":     float(final_score),
    	"category":        category,
    }
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    log(f"Updated report → {report_path}", "OK")
    return final_score, category


# ── CLI entry point ───────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  python classifier.py train              — train model on Drebin dataset")
        print("  python classifier.py score <apk_name>  — score a decompiled APK")
        print("\nExamples:")
        print("  python classifier.py train")
        print("  python classifier.py score Calculator\n")
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "train":
        X, y = load_drebin()
        model, accuracy, auc = train_model(X, y)
        save_model(model, list(X.columns))
        log(f"Model ready! Accuracy: {accuracy*100:.2f}%  AUC: {auc:.4f}", "OK")

    elif command == "score":
        if len(sys.argv) < 3:
            log("Provide APK name. Example: python classifier.py score Calculator", "ERR")
            sys.exit(1)
        apk_name = sys.argv[2]
        score_apk(apk_name)

    else:
        log(f"Unknown command: {command}. Use 'train' or 'score'", "ERR")
        sys.exit(1)


if __name__ == "__main__":
    main()
