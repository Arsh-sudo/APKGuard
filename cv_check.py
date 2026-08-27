import pandas as pd, numpy as np
from sklearn.model_selection import RepeatedStratifiedKFold, cross_validate
from xgboost import XGBClassifier

d = pd.read_csv("data/drebin.csv", sep=";")
y = d["type"].astype(int)
X = d.drop(columns=["type"]).select_dtypes(include=[np.number]).fillna(0)

cv = RepeatedStratifiedKFold(n_splits=5, n_repeats=10, random_state=42)
m = XGBClassifier(n_estimators=100, max_depth=3, learning_rate=0.1,
                  eval_metric="logloss", random_state=42)
s = cross_validate(m, X, y, cv=cv,
                   scoring=["accuracy", "precision", "recall", "f1", "roc_auc"])

print(f"n={len(y)}  features={X.shape[1]}  malware={int(y.sum())}")
for k in ["accuracy", "precision", "recall", "f1", "roc_auc"]:
    v = s["test_" + k]
    print(f"{k:10s} {v.mean():.3f} +/- {v.std():.3f}")