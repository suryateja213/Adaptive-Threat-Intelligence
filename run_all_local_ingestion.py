import logging
import subprocess
import os
from utils.logger import setup_logger

logger = setup_logger("local_main")

def run_all_local_ingestions():
    logger.info("Starting local ingestion pipeline...\n")

    # Run local benign ingestion
    logger.info("Running benign dataset ingestion...")
    subprocess.run(["python", "ingestion/local/local_benign_data.py"], check=True)

    # Run local labeled threat ingestion
    logger.info("Running malicious/labeled dataset ingestion...")
    subprocess.run(["python", "ingestion/local/local_data.py"], check=True)

    logger.info("Local ingestion pipeline completed successfully.")

if __name__ == "__main__":
    run_all_local_ingestions()
