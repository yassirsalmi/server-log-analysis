import logging
from helper.helper import SparkSessionBuilder
from processing.data_cleaning import LogDataCleaner
from ingestion.fetch_logs import fetch_logs
from ingestion.load_to_hdfs import load_to_hdfs

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    source_path = "/home/yassir/Desktop/workspace/server-log-analysis/data/server_logs/logfiles.log"
    local_path = "/tmp/logfiles.log"
    hdfs_input_path = "/data/logfiles.log"
    hdfs_output_path = "/data/cleaned_logs/"
    partition_by = ["year", "month"]
    
    fetch_logs(source_path, local_path)
    load_to_hdfs(local_path, hdfs_input_path)
    
    spark = SparkSessionBuilder.create()
    cleaner = LogDataCleaner(spark)
    
    try:
        cleaner.parse_logs(f"hdfs://{hdfs_input_path}", f"hdfs://{hdfs_output_path}", partition_by)
    finally:
        spark.stop()
        logging.info("Spark session stopped.")