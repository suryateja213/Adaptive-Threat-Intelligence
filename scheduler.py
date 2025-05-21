import schedule
import time
import os
from utils.logger import setup_logger

logger = setup_logger("scheduler")

def run_main_pipeline():
    logger.info("[Scheduler] Triggering main_pipeline.py...")
    exit_code = os.system("python main_pipeline.py")

    if exit_code == 0:
        logger.info("[Scheduler] main_pipeline.py completed successfully \n")
    else:
        logger.error(f"[Scheduler] main_pipeline.py exited with code {exit_code} \n")

# Schedule to run every 24 hours
schedule.every(24).hours.do(run_main_pipeline)

if __name__ == "__main__":
    logger.info("Scheduler started. main_pipeline.py will run every 24 hours.\n")
    
    run_main_pipeline()  # Optional: Run immediately on first launch

    while True:
        schedule.run_pending()
        time.sleep(60)
