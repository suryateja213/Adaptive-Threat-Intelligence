import subprocess
from utils.logger import setup_logger
import sys

logger = setup_logger("main_pipeline")


PYTHON_EXEC = sys.executable

def run_pipeline():
    logger.info("======== STARTING FULL THREAT INTELLIGENCE PIPELINE ========\n")

    # --- Step 1: Run Local Ingestion (Not mandatory (use adhoc [manually upload local datasets and clean the data])) ---
    logger.info("Running local ingestion (benign + labeled threats)...")
    subprocess.run([PYTHON_EXEC, "run_all_local_ingestion.py"], check=True)

    # --- Step 2: Run Cloud Ingestion ---
    logger.info("Running cloud ingestion (ThreatFox, FireHOL, etc.)...")
    subprocess.run([PYTHON_EXEC, "run_all_cloud_ingestion.py"], check=True)

    # --- Step 3: Train Known Threats Model (Supervised) ---
    logger.info("Training supervised model for known threats...")
    subprocess.run([PYTHON_EXEC, "models/train_known_threats_model.py"], check=True)

    # --- Step 4: Train Unknown Threat Detection Model (Unsupervised) ---
    logger.info("Training unsupervised model for unknown threats...")
    subprocess.run([PYTHON_EXEC, "models/train_unknown_threats_model.py"], check=True)

    logger.info("======== FULL PIPELINE EXECUTION COMPLETE ========")

if __name__ == "__main__":
    run_pipeline()
