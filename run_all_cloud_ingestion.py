from ingestion.cloud.phishtank import run_phishtank_ingestion
from ingestion.cloud.malwarebazaar_recent import run_malwarebazaar_recent_ingestion
from ingestion.cloud.firehol_ips import run_firehol_ingestion
from ingestion.cloud.ransomwatch import run_ransomwatch_ingestion
from ingestion.cloud.threatfox import run_threatfox_ingestion
from utils.logger import setup_logger
from ingestion.cloud.merge_cloud_masters import merge_cloud_feeds

logger = setup_logger("main")

def run_all_ingestions():
    logger.info("Running all ingestion tasks...\n")

    run_threatfox_ingestion()
    run_phishtank_ingestion()
    run_malwarebazaar_recent_ingestion()
    run_firehol_ingestion()
    run_ransomwatch_ingestion()
    

    logger.info("All feed ingestions complete. Starting cloud merge...\n")
    
    # Merge master files from all cloud feeds
    merge_cloud_feeds()

    logger.info("Cloud datasets successfully merged and saved.\n")

if __name__ == "__main__":
    run_all_ingestions()
