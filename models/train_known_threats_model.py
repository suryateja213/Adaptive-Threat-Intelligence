import pandas as pd
import os
import logging
import re
import json
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from xgboost import XGBClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.utils import shuffle
import joblib
import multiprocessing
import warnings

warnings.filterwarnings("ignore", category=UserWarning)

def main():
    # === SETUP LOGGING ===
    logs_dir = "training_logs"
    os.makedirs(logs_dir, exist_ok=True)

    log_base_name = "known_threats_training"
    log_files = [f for f in os.listdir(logs_dir) if f.startswith(log_base_name) and f.endswith(".log")]
    log_versions = [int(re.search(r'_v(\d+)\.log$', f).group(1)) for f in log_files if re.search(r'_v(\d+)\.log$', f)]
    log_version = max(log_versions) + 1 if log_versions else 1

    log_file = os.path.join(logs_dir, f"{log_base_name}_v{log_version}.log")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

    logger = logging.getLogger()

    # === CONFIGURATION ===
    benign_path = "data_feeds/processed/benign_local_master_binary.csv"
    local_malicious_path = "data_feeds/processed/local_labeled_threats_binary.csv"
    cloud_base_dir = "data_feeds/processed/cloud"
    model_save_dir = "trained_models"
    os.makedirs(model_save_dir, exist_ok=True)

    # === STEP 1: Load Datasets ===
    logger.info("Loading datasets...")
    df_benign = pd.read_csv(benign_path, low_memory=False)
    df_local_malicious = pd.read_csv(local_malicious_path, low_memory=False)

    with open(os.path.join(cloud_base_dir, "latest_cloud_version.txt")) as f:
        cloud_relative_path = f.read().strip()
    cloud_full_path = os.path.join(cloud_base_dir, cloud_relative_path)
    df_cloud_malicious = pd.read_csv(cloud_full_path, low_memory=False)

    # === STEP 2: Merge Dynamically ===
    logger.info("Merging datasets...")
    df_train = pd.concat([df_benign, df_local_malicious, df_cloud_malicious], ignore_index=True)

    # === STEP 3: Clean and Feature Engineering ===
    logger.info("Cleaning data and feature engineering...")
    df_train = df_train.dropna(subset=["label_binary"])
    df_train["source_encoded"] = df_train["source"].astype("category").cat.codes

    if "url" in df_train.columns:
        df_train["url"] = df_train["url"].astype(str)
        df_train["url_length"] = df_train["url"].apply(len)
        df_train["dot_count"] = df_train["url"].apply(lambda x: x.count('.'))
    else:
        df_train["url_length"] = 0
        df_train["dot_count"] = 0

    # === STEP 4: Define Features and Labels ===
    logger.info("Preparing features and labels...")
    feature_columns = ["source_encoded", "url_length", "dot_count"]
    X = df_train[feature_columns]
    y = df_train["label_binary"]

    # === STEP 5: Shuffle and Split ===
    logger.info("Shuffling and splitting...")
    df_train = shuffle(df_train, random_state=42)
    X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.2, random_state=42)

    # === STEP 6: Build Improved Stacking Model ===
    logger.info("Building improved stacking model...")
    base_models = [
        ('rf', RandomForestClassifier(n_estimators=500, class_weight="balanced", random_state=42)),
        ('xgb', XGBClassifier(n_estimators=500, max_depth=4, learning_rate=0.1, eval_metric='logloss', random_state=42))
    ]

    meta_learner = LogisticRegression(penalty='l2', solver='lbfgs', random_state=42)

    stacked_model = StackingClassifier(estimators=base_models, final_estimator=meta_learner, cv=5, n_jobs=-1)
    stacked_model.fit(X_train, y_train)

    # === STEP 7: Evaluate Model ===
    logger.info("Evaluating model...")
    y_pred = stacked_model.predict(X_test)
    report = classification_report(y_test, y_pred, digits=4)
    logger.info("\n FINAL CLASSIFICATION REPORT:\n" + report)

    # === STEP 8: Save Model with Versioning + Manifest ===
    model_base_name = "known_threat_stacked_model_best"
    existing_models = [f for f in os.listdir(model_save_dir) if f.startswith(model_base_name) and f.endswith(".pkl")]
    model_versions = [int(re.search(r'_v(\d+)\.pkl$', f).group(1)) for f in existing_models if re.search(r'_v(\d+)\.pkl$', f)]
    model_version = max(model_versions) + 1 if model_versions else 1

    model_filename = f"{model_base_name}_v{model_version}.pkl"
    model_save_path = os.path.join(model_save_dir, model_filename)
    joblib.dump(stacked_model, model_save_path)

    # === Save Manifest JSON ===
    manifest = {
        "model_version": f"v{model_version}",
        "trained_on": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "features_used": feature_columns,
        "model_type": "StackingClassifier (RF + XGB + LR)",
        "artifact_file": model_filename,
        "classification_report": report
    }
    manifest_path = os.path.join(model_save_dir, f"{model_base_name}_v{model_version}_manifest.json")
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=4)

    logger.info(f"\n Final improved trained model saved at: {model_save_path}")
    logger.info(f"Training complete. Logs saved at: {log_file}")

if __name__ == "__main__":
    try:
        multiprocessing.set_start_method("spawn", force=True)
    except RuntimeError:
        pass
    import multiprocessing.util
    multiprocessing.util.Finalize(None, lambda: None, exitpriority=0)
    main()
