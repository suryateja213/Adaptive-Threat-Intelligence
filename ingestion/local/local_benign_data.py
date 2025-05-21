import pandas as pd
import os

# Base path
benign_dir = "data_feeds/local_datasets/benign"

# Load all benign datasets
top500 = pd.read_csv(os.path.join(benign_dir, "domains-top-500.csv"))
top1m = pd.read_csv(os.path.join(benign_dir, "top-1m.csv"))
spam_ham = pd.read_csv(os.path.join(benign_dir, "spam_Emails_data.csv"))
github_cleaned = pd.read_csv(os.path.join(benign_dir, "whois_verified_benign_urls.csv"))

# Label top500
top500["label"] = "benign"
top500["label_binary"] = 0
top500["source"] = "top500"

# Label top1m
top1m["label"] = "benign"
top1m["label_binary"] = 0
top1m["source"] = "top1m"

# Correctly label spam_ham dataset
spam_ham["label_binary"] = spam_ham["label"].map({
    "ham": 0,
    "spam": 1
})
spam_ham["label"] = spam_ham["label_binary"].map({
    0: "benign",
    1: "malicious"
})
spam_ham["source"] = "spam_ham"

# Label github_cleaned
github_cleaned["label"] = "benign"
github_cleaned["label_binary"] = 0
github_cleaned["source"] = "github_cleaned"

# Merge all
benign_malicious_combined = pd.concat([top500, top1m, spam_ham, github_cleaned], ignore_index=True)

# Save combined local master
output_path = "data_feeds/processed/benign_local_master_binary.csv"
benign_malicious_combined.to_csv(output_path, index=False)
print(f"Local master (benign + malicious from spam_ham) saved to: {output_path}")
