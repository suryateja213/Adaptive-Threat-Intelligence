import os
import requests
import pandas as pd
from datetime import datetime
from utils.config_loader import load_feed_config
from dotenv import load_dotenv
from utils.logger import setup_logger
from datetime import datetime

logger = setup_logger("threatfox")
load_dotenv()
def fetch_threatfox():
    config = load_feed_config("threatfox")
    api_url = config["api_url"]
    api_key = os.getenv("ABUSECH_API_KEY")
    days = config.get("days", 3)
    raw_path = config["save_path_raw"]

    payload = {
        "query": "get_iocs",
        "days": days
    }
    
    headers = {
        "Auth-Key": api_key,
        "Content-Type": "application/json"
    }

    try:
        logger.info("Fetching ThreatFox IOCs...")
        response = requests.post(api_url, json=payload, headers=headers)
        response.raise_for_status()
        result = response.json()

        if "data" in result:
            df = pd.DataFrame(result["data"])
            df["fetched_at"] = datetime.utcnow().isoformat()
            os.makedirs(os.path.dirname(raw_path), exist_ok=True)
            # Create versioned filename using UTC timestamp
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            versioned_raw_path = os.path.join("data_feeds", "threatfox", "raw", f"threatfox_raw_{timestamp}.csv")
            os.makedirs(os.path.dirname(versioned_raw_path), exist_ok=True)
            df.to_csv(versioned_raw_path, index=False)

            # Optional: Also update the original single file for convenience
            df.to_csv("data_feeds/threatfox_raw.csv", index=False)
            logger.info(f"Saved {len(df)} ThreatFox records to {raw_path}")
            return df, config["save_path_master"]
        else:
            logger.warning("No data in response.")
            return pd.DataFrame(), config["save_path_master"]

    except Exception as e:
        logger.error(f"Error fetching ThreatFox data: {e}")
        return pd.DataFrame(), config["save_path_master"]

def update_master_dataset(new_df, master_path):
    if os.path.exists(master_path):
        existing = pd.read_csv(master_path)
        combined = pd.concat([existing, new_df], ignore_index=True)
        combined = combined.drop_duplicates(subset=["ioc", "first_seen"])
    else:
        combined = new_df.drop_duplicates(subset=["ioc", "first_seen"])

    combined.to_csv(master_path, index=False)
    logger.info(f"Master file updated: {len(combined)} total IOCs.")

def run_threatfox_ingestion():
    new_df, master_path = fetch_threatfox()
    if not new_df.empty:
        update_master_dataset(new_df, master_path)

if __name__ == "__main__":
    run_threatfox_ingestion()
