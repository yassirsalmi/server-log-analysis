from pyspark.sql import functions as F
from pyspark.sql import Window
from pyspark.ml.feature import StandardScaler, VectorAssembler
from pyspark.ml.clustering import KMeans, BisectingKMeans
from pyspark.ml.stat import Summarizer
from pyspark.ml.feature import StringIndexer, OneHotEncoder
from pyspark.sql.types import (
    StructType, StructField, StringType,
    IntegerType, DoubleType, TimestampType
)
import logging
import pandas as pd
import re
from datetime import datetime
from pyod.models.iforest import IForest
from pyspark.ml.feature import VectorAssembler

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s: %(message)s'
)

logger = logging.getLogger(__name__)

class AnomalyDetector:
    def __init__(self, spark_session=None, df=None, spark_df=None, log_file_path=None):
        """
        Initialize the anomaly detector with flexible input options
        
        Args:
            spark_session (pyspark.sql.SparkSession, optional): Spark session
            df (pyspark.sql.DataFrame or pd.DataFrame, optional): Input dataframe
            log_file_path (str, optional): Path to log file
        """
        self.spark = spark_session or spark_df
        self.df = df or spark_df
        self.log_file_path = log_file_path
        self.logs_df = None
        
        # Configuration for web log anomaly detection
        self.config = {
            'suspicious_status_codes': [401, 403, 500, 502, 503],
            'suspicious_http_methods': ['DELETE', 'PUT'],
            'max_requests_per_ip': 100,
            'max_response_time_ms': 5000,
            'unusual_user_agents': ['sqlmap', 'nikto', 'nmap'],
            'geoblocking_countries': [] 
        }

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

    def z_score_detection(self, threshold=2):
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

    def time_series_anomaly_detection(self, window_size=2, threshold=1.5):
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
                    (F.col("rolling_std") > 0) &
                    (F.abs(F.col("request_count") - F.col("rolling_mean")) / F.col("rolling_std") > threshold), 1
                ).otherwise(0)
            )
            logger.info(f"Time series anomaly detection completed. Window size: {window_size}")
            return anomaly_df
        except Exception as e:
            logger.error(f"Error in time series anomaly detection: {str(e)}")
            raise

    def statistical_outlier_detection(self, columns=["request_count", "response_time"], method="zscore"):
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
            
            def detect_zscore_outliers(df, column, threshold=2):
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

    def isolation_forest_detection(df, feature_cols):
        assembler = VectorAssembler(inputCols=feature_cols, outputCol="features")
        feature_df = assembler.transform(df).select("features").toPandas()
        
        model = IForest(contamination=0.1)
        model.fit(feature_df["features"].tolist())
        
        predictions = model.predict(feature_df["features"].tolist())
        df = df.withColumn("isolation_forest_anomaly", F.lit(predictions))
        return df

    def parse_logs(self):
        """
        Parse log file into a pandas DataFrame for analysis
        """
        if not self.log_file_path:
            raise ValueError("No log file path provided")
        
        logs = []
        with open(self.log_file_path, 'r') as f:
            for line in f:
                parsed_log = self.parse_log_line(line)
                if parsed_log:
                    logs.append(parsed_log)
        
        self.logs_df = pd.DataFrame(logs)
        return self.logs_df
    
    def parse_log_line(self, line):
        """
        Parse a single log line
        
        Args:
            line (str): Single log line to parse
        
        Returns:
            dict: Parsed log entry or None if parsing fails
        """
        pattern = r'(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)" (\d+)'
        match = re.match(pattern, line)
        
        if match:
            ip, timestamp, request, status_code, response_size, referrer, user_agent, response_time = match.groups()
            
            try:
                parsed_timestamp = datetime.strptime(timestamp, '%d/%b/%Y:%H:%M:%S %z')
            except:
                parsed_timestamp = None
            
            method, endpoint, protocol = request.split() if request else (None, None, None)
            
            return {
                'ip': ip,
                'timestamp': parsed_timestamp,
                'method': method,
                'endpoint': endpoint,
                'protocol': protocol,
                'status_code': int(status_code),
                'response_size': int(response_size),
                'referrer': referrer,
                'user_agent': user_agent,
                'response_time': int(response_time)
            }
        return None

    def detect_status_code_anomalies(self):
        """
        Detect anomalies based on suspicious HTTP status codes
        
        Returns:
        list: List of dictionaries with status code anomalies
        """
        if self.logs_df is None:
            self.parse_logs() if self.log_file_path else None
        
        suspicious_status_logs = self.logs_df[
            self.logs_df['status_code'].isin(self.config['suspicious_status_codes'])
        ]
        return [{
            'type': 'Suspicious Status Code',
            'ip': row.get('ip', 'Unknown'),
            'status_code': row['status_code'],
            'endpoint': row['endpoint'],
            'timestamp': row['timestamp'].isoformat() if pd.notna(row['timestamp']) else 'Unknown'
        } for _, row in suspicious_status_logs.iterrows()]

    def detect_method_anomalies(self):
        """
        Detect anomalies based on suspicious HTTP methods
        
        Returns:
        list: List of dictionaries with method anomalies
        """
        if self.logs_df is None:
            self.parse_logs() if self.log_file_path else None
        
        suspicious_method_logs = self.logs_df[
            self.logs_df['method'].isin(self.config['suspicious_http_methods'])
        ]
        return [{
            'type': 'Suspicious HTTP Method',
            'ip': row.get('ip', 'Unknown'),
            'method': row['method'],
            'endpoint': row['endpoint'],
            'timestamp': row['timestamp'].isoformat() if pd.notna(row['timestamp']) else 'Unknown'
        } for _, row in suspicious_method_logs.iterrows()]

    def detect_user_agent_anomalies(self):
        """
        Detect anomalies based on unusual user agents
        
        Returns:
        list: List of dictionaries with user agent anomalies
        """
        if self.logs_df is None:
            self.parse_logs() if self.log_file_path else None
        
        unusual_ua_logs = self.logs_df[
            self.logs_df['user_agent'].str.contains('|'.join(self.config['unusual_user_agents']), case=False, na=False)
        ]
        return [{
            'type': 'Unusual User Agent',
            'ip': row.get('ip', 'Unknown'),
            'user_agent': row['user_agent'],
            'endpoint': row['endpoint'],
            'timestamp': row['timestamp'].isoformat() if pd.notna(row['timestamp']) else 'Unknown'
        } for _, row in unusual_ua_logs.iterrows()]

    def detect_ip_anomalies(self):
        """
        Detect anomalies based on high request rates from IPs
        
        Returns:
        list: List of dictionaries with IP anomalies
        """
        if self.logs_df is None:
            self.parse_logs() if self.log_file_path else None
        
        ip_request_counts = self.logs_df['ip'].value_counts()
        high_traffic_ips = ip_request_counts[ip_request_counts > self.config['max_requests_per_ip']]
        return [{
            'type': 'High Request Rate',
            'ip': ip,
            'request_count': int(count),
            'max_allowed_requests': self.config['max_requests_per_ip']
        } for ip, count in high_traffic_ips.items()]

    def detect_performance_anomalies(self):
        """
        Detect performance-related anomalies
        
        Returns:
        list: List of dictionaries with performance anomalies
        """
        if self.logs_df is None:
            self.parse_logs() if self.log_file_path else None
        
        performance_anomalies = []
        
        slow_requests = self.logs_df[self.logs_df['response_time'] > self.config['max_response_time_ms']]
        
        if not slow_requests.empty:
            performance_anomalies.append({
                'type': 'slow_requests',
                'count': len(slow_requests),
                'avg_response_time': slow_requests['response_time'].mean(),
                'max_response_time': slow_requests['response_time'].max()
            })
        
        return performance_anomalies

    def detect_security_anomalies(self):
        """
        Detect security-related anomalies
        
        Returns:
        list: List of dictionaries with security anomalies
        """
        if self.logs_df is None:
            self.parse_logs() if self.log_file_path else None
        
        security_anomalies = []
        
        malicious_ua_logs = self.logs_df[
            self.logs_df['user_agent'].str.contains('|'.join(self.config['unusual_user_agents']), case=False, na=False)
        ]
        
        if not malicious_ua_logs.empty:
            security_anomalies.append({
                'type': 'suspicious_user_agents',
                'details': malicious_ua_logs['user_agent'].value_counts().to_dict()
            })
        
        return security_anomalies

    def detect_log_anomalies(self):
        """
        Comprehensive log anomaly detection combining Spark and Pandas methods.
        
        Returns:
        dict: Dictionary containing anomalies detected by Spark and Pandas methods.
        """
        try:
            if self.logs_df is None:
                raise ValueError("No log data available for analysis")
            
            anomalies = {
                'status_code_anomalies': self.detect_status_code_anomalies(),
                'method_anomalies': self.detect_method_anomalies(),
                'user_agent_anomalies': self.detect_user_agent_anomalies(),
                'ip_anomalies': self.detect_ip_anomalies(),
                'performance_anomalies': self.detect_performance_anomalies(),
                'security_anomalies': self.detect_security_anomalies(),
            }
            
            if hasattr(self.df, 'toPandas'):
                anomalies.update({
                    'z_score_anomalies': self.z_score_detection().toPandas().to_dict(orient='records'),
                    'time_series_anomalies': self.time_series_anomaly_detection().toPandas().to_dict(orient='records')
                })
            
            return anomalies
        except Exception as e:
            logger.error(f"Error in detecting anomalies: {str(e)}")
            return {"error": str(e)}
