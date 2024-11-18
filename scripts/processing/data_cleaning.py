import geoip2.database
from pyspark.sql import DataFrame, SparkSession
from pyspark.sql.functions import (
    regexp_extract, to_timestamp, col, when, length, 
    year, month, udf, split
)
from pyspark.sql.types import TimestampType, StringType, IntegerType
import logging
from typing import Optional, List

class LogDataCleaner:
    def __init__(self, spark: SparkSession, geoip_db_path: str):
        self.spark = spark
        self.geoip_db_path = geoip_db_path

    def parse_logs_from_stream(self, logs_df: DataFrame, output_path: str, checkpoint_path: str, 
                             partition_by: Optional[List[str]] = None) -> None:
        """
        Parse and clean log lines from streaming DataFrame.
        
        Args:
            logs_df (DataFrame): Raw streaming DataFrame from Kafka
            output_path (str): Path to write the processed data
            checkpoint_path (str): Path for streaming checkpoints
            partition_by (Optional[List[str]]): Columns to partition by
        """
        log_pattern = r'(\S+) - - \[(.*?)\] "(.*?)" (\d{3}) (\d+|-) "(.*?)" "(.*?)" (\d+|-)'

        parsed_df = logs_df.select(
            regexp_extract('log_line', log_pattern, 1).alias('ip_address'),
            regexp_extract('log_line', log_pattern, 2).alias('timestamp_raw'),
            regexp_extract('log_line', log_pattern, 3).alias('request'),
            regexp_extract('log_line', log_pattern, 4).alias('status_code'),
            regexp_extract('log_line', log_pattern, 5).alias('response_size'),
            regexp_extract('log_line', log_pattern, 6).alias('referrer'),
            regexp_extract('log_line', log_pattern, 7).alias('user_agent'),
            regexp_extract('log_line', log_pattern, 8).alias('response_time')
        )

        processed_df = self._process_streaming_data(parsed_df)
        
        streaming_query = self._write_streaming_output(
            processed_df, 
            output_path, 
            checkpoint_path,
            partition_by
        )
        
        return streaming_query

    def _process_streaming_data(self, df: DataFrame) -> DataFrame:
        """Process the streaming DataFrame through all transformations."""
        # Clean columns
        cleaned_df = df \
            .withColumn('timestamp', 
                when(length(col('timestamp_raw')) > 0,
                     to_timestamp(col('timestamp_raw'), 'dd/MMM/yyyy:HH:mm:ss Z'))
                .otherwise(None).cast(TimestampType())) \
            .withColumn('status_code',
                when(col('status_code').rlike(r'^\d{3}$'),
                     col('status_code').cast(IntegerType()))
                .otherwise(None)) \
            .withColumn('response_size',
                when(col('response_size').rlike(r'^\d+$'),
                     col('response_size').cast(IntegerType()))
                .otherwise(0)) \
            .withColumn('response_time',
                when(col('response_time').rlike(r'^\d+$'),
                     col('response_time').cast(IntegerType()))
                .otherwise(0))

        enhanced_df = cleaned_df \
            .withColumn("method", 
                when(length(col("request")) > 0,
                     regexp_extract(col("request"), r"^(\S+)", 1))
                .otherwise(None)) \
            .withColumn("endpoint",
                when(length(col("request")) > 0,
                     regexp_extract(col("request"), r"^\S+\s(\S+)", 1))
                .otherwise(None)) \
            .withColumn("protocol",
                when(length(col("request")) > 0,
                     regexp_extract(col("request"), r"(\S+)$", 1))
                .otherwise(None)) \
            .drop("request", "timestamp_raw") \
            .withColumn("year", year(col("timestamp"))) \
            .withColumn("month", month(col("timestamp"))) \
            .withColumn("is_valid_timestamp", col("timestamp").isNotNull()) \
            .withColumn("is_valid_status", col("status_code").isNotNull())

        geoip_db_path = self.geoip_db_path

        def get_geo_info(ip_address: str) -> str:
            if not ip_address:
                return "Unknown|Unknown|Unknown"
                
            try:
                with geoip2.database.Reader(geoip_db_path) as reader:
                    response = reader.city(ip_address)
                    country = response.country.name or "Unknown"
                    city = response.city.name or "Unknown"
                    region = response.subdivisions.most_specific.name if response.subdivisions else "Unknown"
                    return f"{country}|{city}|{region}"
            except Exception as e:
                logging.error(f"GeoIP error for IP {ip_address}: {str(e)}")
                return "Unknown|Unknown|Unknown"

        geo_udf = udf(get_geo_info, StringType())
        
        enriched_df = enhanced_df \
            .withColumn("geo_info", geo_udf("ip_address")) \
            .withColumn("geo_parts", split(col("geo_info"), "\\|")) \
            .withColumn("country", col("geo_parts").getItem(0)) \
            .withColumn("city", col("geo_parts").getItem(1)) \
            .withColumn("region", col("geo_parts").getItem(2)) \
            .drop("geo_info", "geo_parts")

        return enriched_df

    def _write_streaming_output(
        self, 
        df: DataFrame, 
        output_path: str, 
        checkpoint_path: str,
        partition_by: Optional[List[str]] = None
    ):
        """Write streaming DataFrame to output."""
        
        writer = df.writeStream \
            .outputMode("append") \
            .option("checkpointLocation", checkpoint_path)
        
        if partition_by:
            writer = writer.partitionBy(*partition_by)
        
        return writer \
            .format("parquet") \
            .start(output_path)