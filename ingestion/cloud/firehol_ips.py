import os
import pandas as pd
import requests
from datetime import datetime
from utils.logger import setup_logger

logger = setup_logger("firehol")

FEEDS = {
    "level1": "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset",
    "level2": "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level2.netset",
    "level3": "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level3.netset",
}

RAW_DIR = "data_feeds/firehol/raw"
MASTER_FILE = "data_feeds/firehol/firehol_master.csv"

def fetch_firehol_level(level_name, url):
    logger.info(f"Fetching FireHOL {level_name.upper()} IP blocklist...")
    try:
        response = requests.get(url)
        response.raise_for_status()

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        versioned_path = os.path.join(RAW_DIR, f"firehol_{level_name}_{timestamp}.txt")
        os.makedirs(RAW_DIR, exist_ok=True)

        with open(versioned_path, "w") as f:
            f.write(response.text)

        logger.info(f"Saved {len(response.text.splitlines())} IPs from {level_name.upper()}")
        return versioned_path

    except Exception as e:
        logger.error(f"Failed to fetch FireHOL {level_name}: {e}")
        return None

def load_ips_to_df(file_path, level_name):
    try:
        with open(file_path, "r") as f:
            lines = f.read().splitlines()
        df = pd.DataFrame(lines, columns=["ip"])
        df["fetched_at"] = datetime.utcnow().isoformat()
        df["source_file"] = os.path.basename(file_path)
        df["level"] = level_name
        df["malicious"] = 1
        return df
    except Exception as e:
        logger.error(f"Failed to parse {file_path}: {e}")
        return pd.DataFrame()

def update_master_dataset(combined_df):
    if os.path.exists(MASTER_FILE):
        existing_df = pd.read_csv(MASTER_FILE)
        combined = pd.concat([existing_df, combined_df], ignore_index=True)
        combined = combined.drop_duplicates(subset=["ip"])
    else:
        combined = combined_df

    combined.to_csv(MASTER_FILE, index=False)
    logger.info(f"FireHOL master updated: {len(combined)} total IPs.")

def run_firehol_ingestion():
    all_dfs = []

    for level, url in FEEDS.items():
        file_path = fetch_firehol_level(level, url)
        if file_path:
            df = load_ips_to_df(file_path, level)
            if not df.empty:
                all_dfs.append(df)

    if all_dfs:
        combined_df = pd.concat(all_dfs, ignore_index=True)
        update_master_dataset(combined_df)
    else:
        logger.warning("No FireHOL data was fetched.")

if __name__ == "__main__":
    run_firehol_ingestion()
