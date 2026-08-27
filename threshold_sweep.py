import pandas as pd, numpy as np
from sklearn.model_selection import RepeatedStratifiedKFold, cross_val_predict
from xgboost import XGBClassifier

d = pd.read_csv("data/drebin.csv", sep=";")
y = d["type"].astype(int).values
X = d.drop(columns=["type"]).select_dtypes(include=[np.number]).fillna(0)

m = XGBClassifier(n_estimators=100, max_depth=3, learning_rate=0.1,
                  eval_metric="logloss", random_state=42)
cv = RepeatedStratifiedKFold(n_splits=5, n_repeats=1, random_state=42)
prob = cross_val_predict(m, X, y, cv=cv, method="predict_proba")[:, 1]

print(f"{'thresh':>7} {'recall':>7} {'spec':>7} {'FPR':>7} "
      f"{'prec@1%':>8} {'alarms/catch':>13}")
print("-" * 56)
for t in (0.50, 0.70, 0.80, 0.90, 0.95, 0.98, 0.99):
    pred = (prob >= t).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    rec = tp / (tp + fn) if tp + fn else 0
    spec = tn / (tn + fp) if tn + fp else 0
    # Project onto 10,000 apps at 1% malware prevalence
    TP, FP = 100 * rec, 9900 * (1 - spec)
    prec = TP / (TP + FP) if TP + FP else 0
    ratio = FP / TP if TP else float("inf")
    print(f"{t:>7.2f} {rec:>7.3f} {spec:>7.3f} {1-spec:>7.3f} "
          f"{prec:>8.3f} {ratio:>13.1f}")