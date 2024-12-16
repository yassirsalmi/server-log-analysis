import logging
from helper.helper import SparkSessionBuilder
from processing.data_cleaning import LogDataCleaner
from analysis.analytics import LogAnalytics
from analysis.anomaly_detection import AnomalyDetector
from pyspark.sql.types import StructType, StructField, StringType, TimestampType, IntegerType
import os
from pyspark.sql.functions import col

def main():
    logging.basicConfig(level=logging.INFO)
    
    kafka_bootstrap_servers = "localhost:9092"
    kafka_topic = "server_logs"
    hdfs_output_path = "/data/cleaned_logs/"
    partition_by = ["year", "month"]
    geoip_db_path = '/home/yassir/Desktop/workspace/server-log-analysis/GeoLite_data/GeoLite2-City.mmdb'

    cleaned_logs_schema = StructType([
        StructField("ip_address", StringType(), True),
        StructField("timestamp", TimestampType(), True),
        StructField("status_code", IntegerType(), True),
        StructField("response_size", IntegerType(), True),
        StructField("referrer", StringType(), True),
        StructField("user_agent", StringType(), True),
        StructField("response_time", IntegerType(), True),
        StructField("method", StringType(), True),
        StructField("endpoint", StringType(), True),
        StructField("protocol", StringType(), True),
        StructField("year", IntegerType(), True),
        StructField("month", IntegerType(), True),
        StructField("is_valid_timestamp", StringType(), True),
        StructField("is_valid_status", StringType(), True),
        StructField("country", StringType(), True),
        StructField("city", StringType(), True),
        StructField("region", StringType(), True)
    ])

    logging.info("Initializing Spark session...")
    spark = SparkSessionBuilder.create()
    logging.info("Spark session initialized.")
    
    cleaner = LogDataCleaner(spark, geoip_db_path)

    try:
        logging.info(f"Reading from Kafka topic: {kafka_topic}...")
        raw_df = spark.readStream.format("kafka") \
            .option("kafka.bootstrap.servers", kafka_bootstrap_servers) \
            .option("subscribe", kafka_topic) \
            .option("startingOffsets", "latest") \
            .load()
        logging.info("Data read from Kafka successfully.")
        
        logs_df = raw_df.selectExpr("CAST(value AS STRING) as log_line")
        logging.info("Log data extracted and transformed.")
        
        logging.info("Starting streaming process...")
        streaming_query = cleaner.parse_logs_from_stream(
            logs_df=logs_df,
            output_path=hdfs_output_path,
            checkpoint_path="/data/checkpoints/",
            partition_by=partition_by
        )
        
        def read_batch_data():
            try:
                if spark._jvm.org.apache.hadoop.fs.FileSystem.get(
                    spark._jsc.hadoopConfiguration()
                ).exists(
                    spark._jvm.org.apache.hadoop.fs.Path(hdfs_output_path)
                ):
                    return spark.read.schema(cleaned_logs_schema).parquet(hdfs_output_path)
                else:
                    logging.info("No data available yet in the output location.")
                    return None
            except Exception as e:
                logging.error(f"Error reading batch data: {e}")
                return None

        def perform_analytics():
            batch_df = read_batch_data()
            if batch_df is not None and not batch_df.isEmpty():
                try:
                    log_analytics = LogAnalytics(spark, batch_df)
                    anomaly_detection = AnomalyDetector(spark, batch_df)

                    logging.info("Performing descriptive statistics...")
                    stats = log_analytics.descriptive_stats()
                    stats.show()

                    logging.info("Performing time-based analysis (hourly)...")
                    hourly_analysis = log_analytics.time_based_analysis("hour")
                    hourly_analysis.show()

                    logging.info("Performing top N analysis...")
                    common_ips, common_methods, common_endpoints = log_analytics.common_patterns()
                    common_ips.show()

                    logging.info("Performing anomaly detection...")
                    z_scores = anomaly_detection.z_score_detection(threshold=3)
                    z_scores.show()

                    clusters = anomaly_detection.k_means_clustering(num_clusters=3)
                    clusters.show()
                except Exception as e:
                    logging.error(f"Analytics error: {e}")
            else:
                logging.info("Waiting for data to be available for analysis...")

        from apscheduler.schedulers.background import BackgroundScheduler
        scheduler = BackgroundScheduler()
        scheduler.add_job(perform_analytics, 'interval', minutes=5)
        scheduler.start()

        # Wait the streaming query to terminate ( !blan dyal performing select ola ay query makhdamch )
        streaming_query.awaitTermination()
        
    except Exception as e:
        logging.error(f"An error occurred: {e}")
    finally:
        logging.info("Stopping Spark session...")
        spark.stop()
        logging.info("Spark session stopped.")

if __name__ == "__main__":
    main()