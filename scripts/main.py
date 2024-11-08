import logging
from helper.helper import SparkSessionBuilder
from processing.data_cleaning import LogDataCleaner

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    input_path = "/data/logfiles.log"
    output_path = "/data/cleaned_logs/"
    partition_by = ["year", "month"]
    
    spark = SparkSessionBuilder.create()
    cleaner = LogDataCleaner(spark)
    
    try:
        cleaner.parse_logs(input_path, output_path, partition_by)
    finally:
        spark.stop()
