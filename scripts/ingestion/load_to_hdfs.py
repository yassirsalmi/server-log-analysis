import os
import subprocess
import logging

def load_to_hdfs(local_path: str, hdfs_path: str) -> None:
    """
    Load a local file into HDFS.
    
    Args:
        local_path (str): Path to the local file.
        hdfs_path (str): Destination path on HDFS.
    """
    try:
        subprocess.run(["hdfs", "dfs", "-rm", hdfs_path], check=False)  # Delete existing file if any
        subprocess.run(["hdfs", "dfs", "-mkdir", "-p", os.path.dirname(hdfs_path)], check=True)
        subprocess.run(["hdfs", "dfs", "-put", local_path, hdfs_path], check=True)
        logging.info(f"Loaded {local_path} to {hdfs_path} on HDFS")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to load file to HDFS: {e}")