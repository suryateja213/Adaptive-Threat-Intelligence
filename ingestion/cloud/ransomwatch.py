import os
import json
import pandas as pd
import requests
from datetime import datetime
from utils.logger import setup_logger

logger = setup_logger("ransomwatch")

FEED_URL = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
RAW_DIR = "data_feeds/ransomwatch/raw"
RAW_FILE = "data_feeds/ransomwatch/ransomwatch_raw.json"
MASTER_FILE = "data_feeds/ransomwatch/ransomwatch_master.csv"

def fetch_ransomwatch():
    try:
        logger.info("Fetching RansomWatch data...")
        response = requests.get(FEED_URL)
        response.raise_for_status()

        os.makedirs(RAW_DIR, exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        versioned_path = os.path.join(RAW_DIR, f"ransomwatch_raw_{timestamp}.json")

        with open(versioned_path, "w", encoding="utf-8") as f:
            f.write(response.text)

        with open(RAW_FILE, "w", encoding="utf-8") as f:
            f.write(response.text)

        logger.info(f"RansomWatch raw data saved: {versioned_path}")
        return versioned_path

    except Exception as e:
        logger.error(f"Failed to fetch RansomWatch data: {e}")
        return None

def parse_ransomwatch_to_df(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        records = []
        for item in data:
            records.append({
                "group_name": item.get("group_name"),
                "site": item.get("site"),
                "title": item.get("post_title"),
                "date_added": item.get("date"),
                "description": item.get("description", ""),
                "fetched_at": datetime.utcnow().isoformat(),
                "source_file": os.path.basename(file_path),
                "malicious": 1
            })

        return pd.DataFrame(records)

    except Exception as e:
        logger.error(f"Failed to parse RansomWatch JSON: {e}")
        return pd.DataFrame()

def update_master_dataset(new_df):
    if os.path.exists(MASTER_FILE):
        existing = pd.read_csv(MASTER_FILE)
        combined = pd.concat([existing, new_df], ignore_index=True)
        combined = combined.drop_duplicates(subset=["group_name", "site", "title"])
    else:
        combined = new_df

    combined.to_csv(MASTER_FILE, index=False)
    logger.info(f"RansomWatch master updated: {len(combined)} total records.")

def run_ransomwatch_ingestion():
    raw_file = fetch_ransomwatch()
    if not raw_file:
        return

    new_df = parse_ransomwatch_to_df(raw_file)
    if not new_df.empty:
        update_master_dataset(new_df)

if __name__ == "__main__":
    run_ransomwatch_ingestion()
