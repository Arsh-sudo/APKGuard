import pandas as pd, numpy as np
from sklearn.model_selection import RepeatedStratifiedKFold, cross_val_predict
from sklearn.metrics import confusion_matrix
from xgboost import XGBClassifier

d = pd.read_csv("data/drebin.csv", sep=";")
y = d["type"].astype(int)
X = d.drop(columns=["type"]).select_dtypes(include=[np.number]).fillna(0)

m = XGBClassifier(n_estimators=100, max_depth=3, learning_rate=0.1,
                  eval_metric="logloss", random_state=42)
cv = RepeatedStratifiedKFold(n_splits=5, n_repeats=1, random_state=42)
pred = cross_val_predict(m, X, y, cv=cv)
tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
print(f"TN {tn}  FP {fp}  FN {fn}  TP {tp}")

rec, spec = tp/(tp+fn), tn/(tn+fp)
print(f"\nrecall {rec:.3f}  specificity {spec:.3f}")
print("\nPrecision at real-world prevalence (10,000 apps):")
for p in (0.50, 0.10, 0.01, 0.001):
    mal = 10000*p
    TP, FP = mal*rec, (10000-mal)*(1-spec)
    print(f"  {p*100:>5.1f}% malware -> {TP:6.0f} caught, {FP:6.0f} false alarms, "
          f"precision {TP/(TP+FP):.3f}")