"""
APKGuard - Ablation study
=========================

Question this answers: is the 60/40 ML-heuristic blend in classifier.py
earning its place, or is it costing accuracy?

That blend is the ONLY channel through which code-level evidence (obfuscation,
suspicious API keywords, hardcoded IPs) reaches the final verdict, because the
XGBoost model is trained purely on manifest permissions. So the weight is not
cosmetic - it decides how much the rule-based signal is allowed to move the
score.

The full heuristic needs real APKs, but its permission component is computable
straight from the Drebin features, so the comparison runs on all 398 samples.

Run:  py ablation.py
"""

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import RepeatedStratifiedKFold, cross_val_predict
from xgboost import XGBClassifier

# -- Load ------------------------------------------------------------------
d = pd.read_csv("data/drebin.csv", sep=";")
y = d["type"].astype(int).values
X = d.drop(columns=["type"]).select_dtypes(include=[np.number]).fillna(0)

nz = (X != 0).sum()
print(f"samples {len(y)} | malware {int(y.sum())} | benign {int((y == 0).sum())}")
print(f"features {X.shape[1]} | always-zero {int((nz == 0).sum())} | "
      f"seen in <5 rows {int(((nz > 0) & (nz < 5)).sum())} | "
      f"seen in >=20 rows {int((nz >= 20).sum())}")

# -- Heuristic, using decompiler.py's own permission weights ---------------
WEIGHTS = {
    "READ_SMS": 15, "SEND_SMS": 15, "RECEIVE_SMS": 12,
    "BIND_ACCESSIBILITY_SERVICE": 20, "SYSTEM_ALERT_WINDOW": 18,
    "REQUEST_INSTALL_PACKAGES": 18, "READ_CONTACTS": 8, "READ_CALL_LOG": 8,
    "RECORD_AUDIO": 10, "CAMERA": 8, "ACCESS_FINE_LOCATION": 7,
    "READ_PHONE_STATE": 7, "PROCESS_OUTGOING_CALLS": 10,
    "ACCESS_COARSE_LOCATION": 5, "RECEIVE_BOOT_COMPLETED": 5,
}

heuristic = np.zeros(len(d), dtype=float)
used, missing = [], []
for perm, weight in WEIGHTS.items():
    col = "android.permission." + perm
    if col in X.columns:
        heuristic = heuristic + X[col].values * weight
        used.append(perm)
    else:
        missing.append(perm)
heuristic = np.minimum(heuristic, 100.0)

print(f"\nheuristic uses {len(used)}/{len(WEIGHTS)} weighted permissions")
if missing:
    print(f"  not present in dataset: {', '.join(missing)}")

# -- ML, cross-validated so nothing is scored by a model that saw it -------
model = XGBClassifier(
    n_estimators=100, max_depth=3, learning_rate=0.1,
    eval_metric="logloss", random_state=42,
)
cv = RepeatedStratifiedKFold(n_splits=5, n_repeats=1, random_state=42)
ml = cross_val_predict(model, X, y, cv=cv, method="predict_proba")[:, 1]

# -- Compare ---------------------------------------------------------------
ml_100 = ml * 100.0
blend = 0.6 * ml_100 + 0.4 * heuristic

print("\n" + "-" * 48)
print(f"{'scoring method':<30}{'ROC-AUC':>9}{'PR-AUC':>9}")
print("-" * 48)
for label, score in (
    ("heuristic alone", heuristic),
    ("ML alone", ml_100),
    ("blend 0.6 ML / 0.4 heuristic", blend),
):
    print(f"{label:<30}{roc_auc_score(y, score):>9.3f}"
          f"{average_precision_score(y, score):>9.3f}")
print("-" * 48)

# -- Sweep the blend weight ------------------------------------------------
print("\nML weight sweep (0.0 = heuristic only, 1.0 = ML only)")
print(f"{'weight':>8}{'ROC-AUC':>10}{'PR-AUC':>10}")
best_w, best_auc = 0.0, 0.0
for w in np.arange(0.0, 1.01, 0.1):
    combined = w * ml_100 + (1.0 - w) * heuristic
    auc = roc_auc_score(y, combined)
    ap = average_precision_score(y, combined)
    marker = ""
    if auc > best_auc:
        best_auc, best_w = auc, w
    if abs(w - 0.6) < 1e-9:
        marker = "  <- current setting"
    print(f"{w:>8.1f}{auc:>10.3f}{ap:>10.3f}{marker}")

print(f"\nbest ML weight: {best_w:.1f} (ROC-AUC {best_auc:.3f})")
print(f"current setting: 0.6 (ROC-AUC {roc_auc_score(y, blend):.3f})")

delta = best_auc - roc_auc_score(y, blend)
if delta > 0.005:
    print(f"\nThe 60/40 blend costs {delta:.3f} ROC-AUC against the best weight.")
    print("Re-derive the weight from this curve, or drop the blend.")
else:
    print("\nThe 60/40 blend is within noise of the best weight. Keep it, "
          "but say in the README that it was measured rather than assumed.")

print("\nNOTE: this tests only the PERMISSION part of the heuristic. The code-level")
print("signals (obfuscation, API keywords, hardcoded IPs) need real APKs and are")
print("not represented here, so the heuristic is handicapped in this comparison.")
