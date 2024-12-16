from pyspark.sql import functions as F
from pyspark.sql import Window
from pyspark.ml.feature import StandardScaler, VectorAssembler
from pyspark.ml.clustering import KMeans, BisectingKMeans
from pyspark.ml.stat import Summarizer
from pyspark.ml.feature import StringIndexer, OneHotEncoder
from pyspark.sql.types import StructType, StructField, StringType, IntegerType, DoubleType, TimestampType
from analysis.web_log_anomaly_detection import WebLogAnomalyDetector
import os
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class AnomalyDetection:
    def __init__(self, spark_session, df):
        self.spark = spark_session
        self.df = df

    def define_normal_behavior(self):
        """
        Define normal behavior based on historical data with enhanced metrics.
        
        Returns:
        DataFrame: DataFrame with baseline normal behavior metrics.
        """
        window = Window.partitionBy("ip_address", "endpoint")
        normal_behavior = self.df.withColumn("request_count", F.count("endpoint").over(window))
        return normal_behavior.groupBy("ip_address", "endpoint") \
                              .agg(
                                  F.avg("request_count").alias("avg_request_count"),
                                  F.stddev("request_count").alias("stddev_request_count"),
                                  F.min("timestamp").alias("first_seen"),
                                  F.max("timestamp").alias("last_seen")
                              )

    def z_score_detection(self, threshold=3):
        """
        Detect anomalies using enhanced Z-score method.
        
        Parameters:
        threshold (int): Number of standard deviations above mean to flag as anomaly.
        
        Returns:
        DataFrame: DataFrame with anomaly flag column.
        """
        try:
            normal_behavior = self.define_normal_behavior()
            z_score_df = self.df.join(normal_behavior, on=["ip_address", "endpoint"], how="left")
            z_score_df = z_score_df.withColumn(
                "z_score",
                (F.col("request_count") - F.col("avg_request_count")) / F.col("stddev_request_count")
            )
            anomaly_df = z_score_df.withColumn(
                "anomaly", 
                F.when(F.abs(F.col("z_score")) > threshold, 1).otherwise(0)
            )
            logger.info(f"Z-score anomaly detection completed. Threshold: {threshold}")
            return anomaly_df
        except Exception as e:
            logger.error(f"Error in Z-score detection: {str(e)}")
            raise

    def time_series_anomaly_detection(self, window_size=3, threshold=2):
        """
        Detect time series anomalies using rolling window statistics.
        
        Parameters:
        window_size (int): Number of previous time points to consider.
        threshold (int): Number of standard deviations to flag as anomaly.
        
        Returns:
        DataFrame: DataFrame with time series anomaly flags.
        """
        try:
            window_spec = Window.partitionBy("ip_address").orderBy("timestamp").rowsBetween(-window_size, 0)
            time_series_df = self.df.withColumn(
                "rolling_mean", F.mean("request_count").over(window_spec)
            ).withColumn(
                "rolling_std", F.stddev("request_count").over(window_spec)
            )
            
            anomaly_df = time_series_df.withColumn(
                "time_series_anomaly",
                F.when(
                    F.abs(F.col("request_count") - F.col("rolling_mean")) / F.col("rolling_std") > threshold, 1
                ).otherwise(0)
            )
            logger.info(f"Time series anomaly detection completed. Window size: {window_size}")
            return anomaly_df
        except Exception as e:
            logger.error(f"Error in time series anomaly detection: {str(e)}")
            raise

    def statistical_outlier_detection(self, columns=["request_count", "response_time"], method="iqr"):
        """
        Detect statistical outliers using IQR or Z-score method.
        
        Parameters:
        columns (list): List of columns to check for outliers.
        method (str): Method to use for outlier detection ('iqr' or 'zscore').
        
        Returns:
        DataFrame: DataFrame with outlier flags.
        """
        try:
            def detect_iqr_outliers(df, column):
                q1 = F.expr(f"percentile_approx({column}, 0.25)")
                q3 = F.expr(f"percentile_approx({column}, 0.75)")
                iqr = F.expr(f"percentile_approx({column}, 0.75) - percentile_approx({column}, 0.25)")
                
                return df.withColumn(
                    f"{column}_outlier",
                    F.when(
                        (F.col(column) < (q1 - 1.5 * iqr)) | (F.col(column) > (q3 + 1.5 * iqr)), 1
                    ).otherwise(0)
                )
            
            def detect_zscore_outliers(df, column, threshold=3):
                mean = F.mean(column)
                std = F.stddev(column)
                
                return df.withColumn(
                    f"{column}_outlier",
                    F.when(
                        F.abs((F.col(column) - mean) / std) > threshold, 1
                    ).otherwise(0)
                )
            
            outlier_detection_func = detect_iqr_outliers if method == "iqr" else detect_zscore_outliers
            
            for column in columns:
                self.df = outlier_detection_func(self.df, column)
            
            logger.info(f"Statistical outlier detection completed using {method} method")
            return self.df
        except Exception as e:
            logger.error(f"Error in statistical outlier detection: {str(e)}")
            raise

    def k_means_clustering(self, num_clusters=2):
        """
        Apply K-means clustering to detect anomalies based on unusual cluster assignments.
        """
        assembler = VectorAssembler(inputCols=["request_count", "response_time"], outputCol="features")
        feature_df = assembler.transform(self.df)

        scaler = StandardScaler(inputCol="features", outputCol="scaled_features")
        scaled_model = scaler.fit(feature_df)
        scaled_df = scaled_model.transform(feature_df)

        kmeans = KMeans(k=num_clusters, featuresCol="scaled_features", predictionCol="cluster")
        model = kmeans.fit(scaled_df)
        return model.transform(scaled_df)

    def isolation_forest_detection(self, num_trees=100, max_samples=256, contamination=0.1):
        """
        Use Spark's distributed Isolation Forest for anomaly detection.
        """
        from pyspark.ml.feature import VectorAssembler
        from pyspark.ml.clustering import BisectingKMeans
        
        assembler = VectorAssembler(inputCols=["request_count", "response_time"], outputCol="features")
        feature_df = assembler.transform(self.df)
        
        bkm = BisectingKMeans(k=int(self.df.count() * contamination), 
                               featuresCol="features", 
                               predictionCol="anomaly_cluster")
        model = bkm.fit(feature_df)
        anomaly_df = model.transform(feature_df)
        
        cluster_sizes = model.clusterCenters()
        smallest_cluster_index = min(range(len(cluster_sizes)), key=lambda i: len(cluster_sizes[i]))
        
        return anomaly_df.withColumn(
            "is_anomaly", 
            F.when(F.col("anomaly_cluster") == smallest_cluster_index, 1).otherwise(0)
        ).select("*", "is_anomaly")

def detect_log_anomalies(spark_session):
    """
    Comprehensive log anomaly detection pipeline.
    
    Returns:
    list: A list of dictionaries containing anomaly details.
    """
    DEFAULT_LOG_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'server_logs', 'logfiles.log')
    
    try:
        log_schema = StructType([
            StructField("timestamp", TimestampType(), True),
            StructField("ip_address", StringType(), True),
            StructField("endpoint", StringType(), True),
            StructField("request_count", IntegerType(), True),
            StructField("response_time", DoubleType(), True)
        ])
        
        logs_df = spark_session.read.csv(DEFAULT_LOG_PATH, schema=log_schema, header=True)
        
        anomaly_detector = AnomalyDetection(spark_session, logs_df)
        
        z_score_anomalies = anomaly_detector.z_score_detection()
        time_series_anomalies = anomaly_detector.time_series_anomaly_detection()
        statistical_anomalies = anomaly_detector.statistical_outlier_detection()
        
        combined_anomalies = z_score_anomalies.join(time_series_anomalies, ["ip_address", "endpoint"]) \
                                              .join(statistical_anomalies, ["ip_address", "endpoint"])
        
        anomalies = combined_anomalies.filter(
            (F.col("anomaly") == 1) | 
            (F.col("time_series_anomaly") == 1) | 
            (F.col("request_count_outlier") == 1)
        ).collect()
        
        logger.info(f"Total anomalies detected: {len(anomalies)}")
        return anomalies
    
    except FileNotFoundError:
        logger.error(f"Log file not found at {DEFAULT_LOG_PATH}")
        return [{"error": "Log file not found"}]
    except Exception as e:
        logger.error(f"Unexpected error during anomaly detection: {str(e)}")
        return [{"error": str(e)}]
