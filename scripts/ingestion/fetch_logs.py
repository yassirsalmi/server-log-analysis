import os
import shutil
import logging

def fetch_logs(source_path: str, local_path: str) -> None:
    """
    Fetch log files from a source path and save them locally.
    
    Args:
        source_path (str): Path to the source log file.
        local_path (str): Path to save the fetched log file locally.
    """
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    shutil.copy(source_path, local_path)
    logging.info(f"Fetched logs from {source_path} to {local_path}")
