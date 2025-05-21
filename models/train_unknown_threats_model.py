import pandas as pd
import numpy as np
import os
import logging
import re
import json
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, precision_recall_curve, f1_score
from sklearn.model_selection import train_test_split
from scipy.spatial import distance
import joblib
import multiprocessing

def main():
    # === SETUP LOGGING ===
    logs_dir = "training_logs"
    os.makedirs(logs_dir, exist_ok=True)

    log_base_name = "unsupervised_unknown_threats"
    log_files = [f for f in os.listdir(logs_dir) if f.startswith(log_base_name) and f.endswith(".log")]
    log_versions = [int(re.search(r'_v(\d+)\.log$', f).group(1)) for f in log_files if re.search(r'_v(\d+)\.log$', f)]
    log_version = max(log_versions) + 1 if log_versions else 1

    log_file = os.path.join(logs_dir, f"{log_base_name}_v{log_version}.log")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()]
    )

    logger = logging.getLogger()

    # === CONFIGURATION ===
    benign_path = "data_feeds/processed/benign_local_master_binary.csv"
    malicious_path = "data_feeds/processed/local_labeled_threats_binary.csv"
    root_model_dir = "trained_models"
    os.makedirs(root_model_dir, exist_ok=True)

    # === STEP 1: Load datasets ===
    logger.info("Loading datasets...")
    df_benign = pd.read_csv(benign_path, low_memory=False)
    df_malicious = pd.read_csv(malicious_path, low_memory=False)

    df_benign["true_label"] = 0
    df_malicious["true_label"] = 1

    df_all = pd.concat([df_benign, df_malicious], ignore_index=True)

    # === STEP 2: Feature Engineering ===
    logger.info("Performing comprehensive feature engineering...")

    categorical_features = ["source", "protocol", "service"]
    for feature in categorical_features:
        if feature in df_all.columns:
            df_all[f"{feature}_encoded"] = LabelEncoder().fit_transform(df_all[feature].astype(str))
        else:
            logger.warning(f"Column '{feature}' not found in dataset. Skipping encoding.")

    df_all["url_length"] = df_all["url"].astype(str).apply(len)
    df_all["dot_count"] = df_all["url"].astype(str).apply(lambda x: x.count('.'))
    df_all["hyphen_count"] = df_all["url"].astype(str).apply(lambda x: x.count('-'))
    df_all["slash_count"] = df_all["url"].astype(str).apply(lambda x: x.count('/'))

    features = [col for col in [
        "source_encoded", "protocol_encoded", "service_encoded",
        "url_length", "dot_count", "hyphen_count", "slash_count"
    ] if col in df_all.columns]

    X = df_all[features]
    y_true = df_all["true_label"]

    # === STEP 3: Standardize Features ===
    logger.info("Standardizing features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_benign_scaled = X_scaled[y_true == 0]

    # === STEP 4: Train Isolation Forest & Mahalanobis on benign data ===
    logger.info("Training Isolation Forest and calculating Mahalanobis distance...")

    iso_forest = IsolationForest(n_estimators=150, contamination=0.02, random_state=42, n_jobs=-1)
    iso_forest.fit(X_benign_scaled)

    mean_benign = np.mean(X_benign_scaled, axis=0)
    cov_benign = np.cov(X_benign_scaled, rowvar=False)
    inv_cov_benign = np.linalg.inv(cov_benign)

    # === STEP 5: Generate Meta Features ===
    logger.info("Generating meta-features using anomaly models...")
    iso_scores = -iso_forest.decision_function(X_scaled)
    mahalanobis_distances = np.array([
        distance.mahalanobis(x, mean_benign, inv_cov_benign) for x in X_scaled
    ])

    meta_features = np.column_stack((iso_scores, mahalanobis_distances))

    # === STEP 6: Train-Test Split ===
    X_train, X_test, y_train, y_test = train_test_split(
        meta_features, y_true, test_size=0.2, stratify=y_true, random_state=42
    )

    # === STEP 7: Train Meta-classifier ===
    logger.info("Training logistic regression meta-classifier...")
    meta_classifier = LogisticRegression(penalty='l2', solver='lbfgs', max_iter=1500, random_state=42)
    meta_classifier.fit(X_train, y_train)

    # === STEP 8: Evaluate Default Threshold ===
    logger.info("Evaluating model with default threshold...")
    y_pred_default = meta_classifier.predict(X_test)
    default_report = classification_report(y_test, y_pred_default, digits=4)
    logger.info("\nDEFAULT THRESHOLD CLASSIFICATION REPORT:\n" + default_report)

    # === STEP 9: Threshold Tuning ===
    logger.info("Optimizing threshold based on F1-score...")
    y_proba = meta_classifier.predict_proba(X_test)[:, 1]
    precisions, recalls, thresholds = precision_recall_curve(y_test, y_proba)

    best_f1, best_threshold = max(
        [(f1_score(y_test, y_proba >= t), t) for t in thresholds if 0.3 <= t <= 0.7],
        default=(0, 0.5)
    )

    logger.info(f"Optimal Threshold: {best_threshold:.4f}, Best F1: {best_f1:.4f}")

    y_pred_tuned = (y_proba >= best_threshold).astype(int)
    tuned_report = classification_report(y_test, y_pred_tuned, digits=4)
    logger.info("\nOPTIMIZED THRESHOLD CLASSIFICATION REPORT:\n" + tuned_report)

    # === STEP 10: Save Artifacts with Versioning in Subfolder ===
    base_folder_prefix = "unsupervised_model_v"
    existing_folders = [d for d in os.listdir(root_model_dir) if d.startswith(base_folder_prefix) and os.path.isdir(os.path.join(root_model_dir, d))]
    folder_versions = [int(re.search(r'_v(\d+)', d).group(1)) for d in existing_folders if re.search(r'_v(\d+)', d)]
    next_version = max(folder_versions) + 1 if folder_versions else 1
    subfolder_name = f"{base_folder_prefix}{next_version}"
    model_save_dir = os.path.join(root_model_dir, subfolder_name)
    os.makedirs(model_save_dir, exist_ok=True)

    logger.info("Saving models and preprocessing parameters...")
    model_base_names = ["iso_forest", "meta_classifier", "scaler", "mahalanobis_params"]
    model_paths = {}

    for base in model_base_names:
        versioned_file = f"{base}_v1{'.npz' if base == 'mahalanobis_params' else '.pkl'}"
        model_paths[base] = os.path.join(model_save_dir, versioned_file)

    joblib.dump(iso_forest, model_paths["iso_forest"])
    joblib.dump(meta_classifier, model_paths["meta_classifier"])
    joblib.dump(scaler, model_paths["scaler"])
    np.savez(model_paths["mahalanobis_params"], mean=mean_benign, inv_cov=inv_cov_benign)

    threshold_path = os.path.join(model_save_dir, "optimal_threshold_v1.txt")
    with open(threshold_path, 'w') as f:
        f.write(str(best_threshold))

    # === Save Manifest ===
    manifest = {
        "model_version": subfolder_name,
        "trained_on": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "features_used": features,
        "threshold": best_threshold,
        "best_f1_score": round(best_f1, 4),
        "artifacts": {
            "iso_forest": os.path.basename(model_paths["iso_forest"]),
            "meta_classifier": os.path.basename(model_paths["meta_classifier"]),
            "scaler": os.path.basename(model_paths["scaler"]),
            "mahalanobis_params": os.path.basename(model_paths["mahalanobis_params"]),
            "threshold_file": os.path.basename(threshold_path)
        }
    }

    manifest_path = os.path.join(model_save_dir, "model_manifest.json")
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=4)

    logger.info(f"Artifacts saved in folder: {subfolder_name}")
    logger.info("Training complete. Logs saved at: {}".format(log_file))

if __name__ == "__main__":
    multiprocessing.set_start_method("spawn", force=True)
    main()
