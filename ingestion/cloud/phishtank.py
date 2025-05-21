import os
import pandas as pd
from datetime import datetime, timedelta
from utils.config_loader import load_feed_config
from utils.logger import setup_logger

logger = setup_logger("phishtank")

def was_run_within_24_hours(last_run_file):
    if not os.path.exists(last_run_file):
        return False
    try:
        with open(last_run_file, "r") as f:
            last_run_str = f.read().strip()
            last_run_time = datetime.fromisoformat(last_run_str)
            return datetime.utcnow() - last_run_time < timedelta(hours=24)
    except Exception as e:
        logger.warning(f"Could not parse last run timestamp: {e}")
        return False

def update_last_run_file(last_run_file):
    with open(last_run_file, "w") as f:
        f.write(datetime.utcnow().isoformat())
        
def fetch_phishtank():
    config = load_feed_config("phishtank")
    url = config["csv_url"]
    raw_path = config["save_path_raw"]
    last_run_file = config.get("last_run_file", "data_feeds/phishtank/last_run.txt")

    # Skip if fetched within last 24 hours
    if was_run_within_24_hours(last_run_file):
        logger.info("Skipping PhishTank fetch — already fetched in last 24 hours.")
        return pd.DataFrame(), config["save_path_master"]

    try:
        logger.info("Fetching PhishTank data...")
        df = pd.read_csv(url)

        # Save timestamped version
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        versioned_raw_path = os.path.join("data_feeds", "phishtank", "raw", f"phishtank_raw_{timestamp}.csv")
        os.makedirs(os.path.dirname(versioned_raw_path), exist_ok=True)
        df.to_csv(versioned_raw_path, index=False)

        # Save latest raw snapshot
        df.to_csv(raw_path, index=False)

        update_last_run_file(last_run_file)

        logger.info(f"Saved {len(df)} PhishTank records.")
        return df, config["save_path_master"]

    except Exception as e:
        logger.error(f"Error fetching PhishTank data: {e}")
        return pd.DataFrame(), config["save_path_master"]

def update_master_dataset(new_df, master_path):
    if os.path.exists(master_path):
        existing = pd.read_csv(master_path)
        combined = pd.concat([existing, new_df], ignore_index=True)
        combined = combined.drop_duplicates(subset=["url", "submission_time"])
    else:
        combined = new_df.drop_duplicates(subset=["url", "submission_time"])

    combined.to_csv(master_path, index=False)
    logger.info(f"Master file updated: {len(combined)} total phishing URLs.")

def run_phishtank_ingestion():
    new_df, master_path = fetch_phishtank()
    if not new_df.empty:
        update_master_dataset(new_df, master_path)

if __name__ == "__main__":
    run_phishtank_ingestion()
