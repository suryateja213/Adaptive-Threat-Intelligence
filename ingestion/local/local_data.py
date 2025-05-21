import pandas as pd
import os

# === File paths under corrected directory ===
base_path = "data_feeds/local_datasets/malicious"

files_info = {
    "android_malware": {
        "path": os.path.join(base_path, "android_malware.csv"),
        "label": "malicious",
        "label_col": None
    },
    "dga_custom": {
        "path": os.path.join(base_path, "dga_custom.csv"),
        "label": "dga",
        "label_col": None
    },
    "malicious_phish": {
        "path": os.path.join(base_path, "malicious_phish.csv"),
        "label_col": "type",
        "label_map": {
            "benign": "benign",
            "phishing": "phishing",
            "malware": "malicious",
            "defacement": "malicious"
        }
    },
    "phishing_site_urls": {
        "path": os.path.join(base_path, "phishing_site_urls.csv"),
        "label_col": "label",
        "label_map": {
            "bad": "phishing",
            "good": "benign"
        }
    },
    "spam_ham": {
        "path": os.path.join(base_path, "spam_ham_dataset.csv"),
        "label_col": "label_num",
        "label_map": {
            1: "malicious",
            0: "benign"
        }
    }
}

# === Processing Function ===
def load_and_label(file, source, label_col=None, label_map=None, default_label=None):
    df = pd.read_csv(file, low_memory=False)
    df["source"] = source

    if label_col:
        col_map = {col.lower(): col for col in df.columns}
        real_label_col = col_map.get(label_col.lower(), label_col)

        if real_label_col not in df.columns:
            raise KeyError(f"Expected label column '{label_col}' not found in {file}")

        df["label"] = df[real_label_col].map(label_map)
    else:
        df["label"] = default_label

    df["label"] = df["label"].fillna("unknown")
    return df

# === Load all datasets ===
all_dfs = []

for source, config in files_info.items():
    df = load_and_label(
        file=config["path"],
        source=source,
        label_col=config.get("label_col"),
        label_map=config.get("label_map"),
        default_label=config.get("label")
    )
    all_dfs.append(df)

# === Merge all into a unified DataFrame ===
unified_local_df = pd.concat(all_dfs, ignore_index=True)

# === Add binary labels for ML training ===
label_map_binary = {
    "malicious": 1,
    "phishing": 1,
    "ransomware": 1,
    "dga": 1,
    "ip_blocklist": 1,
    "benign": 0
}

unified_local_df["label_binary"] = unified_local_df["label"].map(label_map_binary)
unified_local_df = unified_local_df[unified_local_df["label_binary"].notna()]

# === Save to disk ===
output_dir = "data_feeds/processed"
os.makedirs(output_dir, exist_ok=True)
output_path = os.path.join(output_dir, "local_labeled_threats_binary.csv")
unified_local_df.to_csv(output_path, index=False)
print(f"Merged local labeled dataset with binary labels saved to: {output_path}")
