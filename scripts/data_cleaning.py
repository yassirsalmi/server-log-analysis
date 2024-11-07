from pyspark.sql import SparkSession, DataFrame
from pyspark.sql.functions import regexp_extract, to_timestamp, col, when, length, year, month
from pyspark.sql.types import TimestampType, StringType, IntegerType
import logging
from typing import Optional, List
from helper import SparkSessionBuilder

class LogDataCleaner:
    """
    Class to handle parsing and cleaning of log data.
    """
    def __init__(self, spark: SparkSession) -> None:
        self.spark = spark
    
    def parse_logs(self, input_path: str, output_path: str, partition_by: Optional[List[str]] = None) -> DataFrame:
        """
        Parse and clean log files using Spark.
        
        Args:
            input_path (str): Path to input log files.
            output_path (str): Path to write cleaned parquet files.
            partition_by (Optional[List[str]]): Optional columns to partition the output by.
        
        Returns:
            DataFrame: Final cleaned DataFrame.
        """
        log_pattern = r'(\S+) - - \[(.*?)\] "(.*?)" (\d{3}) (\d+|-) "(.*?)" "(.*?)" (\d+|-)'
        
        df = self.spark.read.text(input_path)
        
        parsed_df = df.select(
            regexp_extract('value', log_pattern, 1).alias('ip_address'),
            regexp_extract('value', log_pattern, 2).alias('timestamp_raw'),
            regexp_extract('value', log_pattern, 3).alias('request'),
            regexp_extract('value', log_pattern, 4).alias('status_code'),
            regexp_extract('value', log_pattern, 5).alias('response_size'),
            regexp_extract('value', log_pattern, 6).alias('referrer'),
            regexp_extract('value', log_pattern, 7).alias('user_agent'),
            regexp_extract('value', log_pattern, 8).alias('response_time')
        )
        
        cleaned_df = self._clean_columns(parsed_df)
        final_df = self._enhance_dataframe(cleaned_df, partition_by)

        # showing the first 3 to check
        final_df.show(3, truncate=False)
        
        self._write_output(final_df, output_path, partition_by)
        self._log_summary(final_df)

        return final_df
    
    def _clean_columns(self, df: DataFrame) -> DataFrame:
        """
        Clean and cast columns to appropriate data types.
        
        Args:
            df (DataFrame): Parsed DataFrame.
        
        Returns:
            DataFrame: Cleaned DataFrame with appropriate column types.
        """
        return df \
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

    def _enhance_dataframe(self, df: DataFrame, partition_by: Optional[List[str]]) -> DataFrame:
        """
        Enhance the DataFrame with additional columns for analysis and partitioning.
        
        Args:
            df (DataFrame): Cleaned DataFrame.
            partition_by (Optional[List[str]]): Columns to partition the output by.
        
        Returns:
            DataFrame: Enhanced DataFrame.
        """
        return df \
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

    def _write_output(self, df: DataFrame, output_path: str, partition_by: Optional[List[str]]) -> None:
        """
        Write the final DataFrame to the specified output path.
        
        Args:
            df (DataFrame): Final DataFrame to write.
            output_path (str): Output path for the parquet files.
            partition_by (Optional[List[str]]): Columns to partition the output by.
        """
        writer = df.write.mode("overwrite")
        if partition_by:
            writer = writer.partitionBy(*partition_by)
        writer.parquet(output_path)

    def _log_summary(self, df: DataFrame) -> None:
        """
        Log summary statistics of the DataFrame.
        
        Args:
            df (DataFrame): Final DataFrame for logging.
        """
        row_count = df.count()
        invalid_timestamps = df.filter(~col("is_valid_timestamp")).count()
        invalid_status = df.filter(~col("is_valid_status")).count()
        
        logging.info(f"Processed {row_count} log entries")
        logging.info(f"Found {invalid_timestamps} invalid timestamps")
        logging.info(f"Found {invalid_status} invalid status codes")


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
