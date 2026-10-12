"""
Layer 3: Train the machine learning model.

Steps:
  1. Load the PhiUSIIL dataset (235,795 labelled URLs)
  2. Convert each URL's domain into numbers (ml_features.py)
  3. Split: 80% for training, 20% kept aside for testing
  4. Train and compare 3 models, keep the best one
  5. Save the model, metrics and charts for the report
"""
import json
import os
import time

import joblib
import matplotlib
matplotlib.use("Agg")  # save charts to files without opening windows
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, ConfusionMatrixDisplay)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from ml_features import FEATURE_NAMES, host_features

DATA_PATH = os.path.join("data", "phiusiil_dataset.csv")
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

# ---------- 1. Load ----------
print("Loading dataset...")
df = pd.read_csv(DATA_PATH, usecols=["URL", "label"], encoding="utf-8-sig")
# In PhiUSIIL, label 1 = legitimate, 0 = phishing. We flip it so 1 = phishing.
df["is_phishing"] = 1 - df["label"]
print(f"  {len(df):,} URLs  |  phishing: {df.is_phishing.sum():,}  "
      f"|  legitimate: {(df.is_phishing == 0).sum():,}")

# ---------- 2. Features ----------
print("Extracting domain features (about a minute)...")
t0 = time.time()
X = pd.DataFrame([host_features(u) for u in df["URL"]], columns=FEATURE_NAMES)
y = df["is_phishing"]
print(f"  done in {time.time() - t0:.0f}s")

# ---------- 3. Split ----------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y)

# ---------- 4. Train and compare ----------
models = {
    "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000)),
    "Decision Tree": DecisionTreeClassifier(max_depth=15, random_state=42),
    "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=16,
                                            n_jobs=-1, random_state=42),
}

results = {}
for name, model in models.items():
    print(f"Training {name}...")
    t0 = time.time()
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    results[name] = {
        "accuracy": accuracy_score(y_test, pred),
        "precision": precision_score(y_test, pred),
        "recall": recall_score(y_test, pred),
        "f1": f1_score(y_test, pred),
        "train_seconds": round(time.time() - t0, 1),
    }

print("\n=== Model comparison (on 20% unseen test data) ===")
print(f"{'Model':22}{'Accuracy':>10}{'Precision':>11}{'Recall':>9}{'F1':>8}")
for name, m in results.items():
    print(f"{name:22}{m['accuracy']:>10.4f}{m['precision']:>11.4f}"
          f"{m['recall']:>9.4f}{m['f1']:>8.4f}")

best_name = max(results, key=lambda n: results[n]["f1"])
best = models[best_name]
print(f"\nBest model: {best_name}")

# ---------- 5. Save model, metrics and charts ----------
joblib.dump({"model": best, "features": FEATURE_NAMES, "name": best_name},
            os.path.join(MODEL_DIR, "phishing_model.joblib"), compress=3)

best_pred = best.predict(X_test)
cm = confusion_matrix(y_test, best_pred)
with open(os.path.join(MODEL_DIR, "metrics.json"), "w") as f:
    json.dump({"best_model": best_name, "results": results,
               "confusion_matrix": cm.tolist(),
               "test_size": len(y_test), "train_size": len(y_train)}, f, indent=2)

# Chart 1: confusion matrix
ConfusionMatrixDisplay(cm, display_labels=["Legitimate", "Phishing"]).plot(
    cmap="Blues", values_format=",")
plt.title(f"Confusion Matrix - {best_name}")
plt.tight_layout()
plt.savefig(os.path.join(MODEL_DIR, "confusion_matrix.png"), dpi=150)
plt.close()

# Chart 2: model comparison
names = list(results)
x = range(len(names))
fig, ax = plt.subplots(figsize=(8, 4.5))
for i, metric in enumerate(["accuracy", "precision", "recall", "f1"]):
    ax.bar([p + i * 0.2 for p in x], [results[n][metric] for n in names],
           width=0.2, label=metric.capitalize())
ax.set_xticks([p + 0.3 for p in x])
ax.set_xticklabels(names)
ax.set_ylim(0.5, 1.0)
ax.set_ylabel("Score")
ax.set_title("Model Comparison on Test Data")
ax.legend(loc="lower right")
plt.tight_layout()
plt.savefig(os.path.join(MODEL_DIR, "model_comparison.png"), dpi=150)
plt.close()

# Chart 3: which features matter most (tree models only)
if hasattr(best, "feature_importances_"):
    imp = pd.Series(best.feature_importances_, index=FEATURE_NAMES).sort_values()
    imp.plot.barh(figsize=(8, 5), color="#3b6fd6")
    plt.title(f"Feature Importance - {best_name}")
    plt.xlabel("Importance")
    plt.tight_layout()
    plt.savefig(os.path.join(MODEL_DIR, "feature_importance.png"), dpi=150)
    plt.close()

print(f"Saved model and charts to the '{MODEL_DIR}' folder")

# ---------- Quick check on our own test QR codes ----------
from qr_decoder import decode_qr_from_path
print("\n=== Model predictions on our test QR codes ===")
for name in sorted(os.listdir("test_qrs")):
    url = decode_qr_from_path(os.path.join("test_qrs", name))
    prob = best.predict_proba(pd.DataFrame([host_features(url)], columns=FEATURE_NAMES))[0][1]
    print(f"{name:30} phishing probability: {prob:.0%}")
