import os
import pandas as pd
from logger import setup_logger

logger = setup_logger("bazaar_export_merge")

EXPORT_FILE = "data_feeds/malwarebazaar/export/bazaar_export.csv"
MASTER_FILE = "data_feeds/malwarebazaar/malwarebazaar_master.csv"

def merge_export_into_master():
    if not os.path.exists(EXPORT_FILE):
        logger.error(f"Export file not found: {EXPORT_FILE}")
        return

    try:
        df_export = pd.read_csv(EXPORT_FILE,skiprows=8, on_bad_lines='skip', engine="python")
        df_export["malicious"] = 1
        df_export["source_file"] = os.path.basename(EXPORT_FILE)
        df_export["fetched_at"] = pd.to_datetime("2025-04-23").isoformat()

        if os.path.exists(MASTER_FILE):
            df_master = pd.read_csv(MASTER_FILE)
            combined = pd.concat([df_master, df_export], ignore_index=True)
        else:
            combined = df_export

        combined = combined.drop_duplicates(subset=["sha256_hash"])
        combined.to_csv(MASTER_FILE, index=False)
        logger.info(f"Master file updated with export data. Total entries: {len(combined)}")

    except Exception as e:
        logger.error(f"Failed to merge export into master: {e}")

if __name__ == "__main__":
    merge_export_into_master()
