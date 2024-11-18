from pyspark.sql import functions as F
from pyspark.sql import Window
from pyspark.ml.feature import StandardScaler, VectorAssembler
from pyspark.ml.clustering import KMeans
from pyspark.ml.stat import Summarizer

class AnomalyDetection:
    def __init__(self, spark_session, df):
        self.spark = spark_session
        self.df = df

    def define_normal_behavior(self):
        """
        Define normal behavior based on historical data:
        - Calculates average request count and variance by IP and endpoint.
        
        Returns:
        DataFrame: DataFrame with baseline normal behavior metrics.
        """
        window = Window.partitionBy("ip_address", "endpoint")
        normal_behavior = self.df.withColumn("request_count", F.count("endpoint").over(window))
        return normal_behavior.groupBy("ip_address", "endpoint") \
                              .agg(
                                  F.avg("request_count").alias("avg_request_count"),
                                  F.stddev("request_count").alias("stddev_request_count")
                              )

    def z_score_detection(self, threshold=3):
        """
        Detect anomalies using Z-score method:
        - Flags requests with request count beyond specified threshold from mean.
        
        Parameters:
        threshold (int): Number of standard deviations above mean to flag as anomaly.
        
        Returns:
        DataFrame: DataFrame with anomaly flag column.
        """
        normal_behavior = self.define_normal_behavior()
        z_score_df = self.df.join(normal_behavior, on=["ip_address", "endpoint"], how="left")
        z_score_df = z_score_df.withColumn(
            "z_score",
            (F.col("request_count") - F.col("avg_request_count")) / F.col("stddev_request_count")
        )
        return z_score_df.withColumn("anomaly", F.when(F.abs(F.col("z_score")) > threshold, 1).otherwise(0))

    def k_means_clustering(self, num_clusters=2):
        """
        Apply K-means clustering to detect anomalies based on unusual cluster assignments.
        
        Parameters:
        num_clusters (int): Number of clusters for K-means model.
        
        Returns:
        DataFrame: DataFrame with cluster assignments.
        """
        assembler = VectorAssembler(inputCols=["request_count", "response_time"], outputCol="features")
        feature_df = assembler.transform(self.df)

        scaler = StandardScaler(inputCol="features", outputCol="scaled_features")
        scaled_model = scaler.fit(feature_df)
        scaled_df = scaled_model.transform(feature_df)

        kmeans = KMeans(k=num_clusters, featuresCol="scaled_features", predictionCol="cluster")
        model = kmeans.fit(scaled_df)
        return model.transform(scaled_df)

    def isolation_forest_detection(self, pandas_df, contamination=0.1):
        """
        Use Isolation Forest for anomaly detection (requires exporting data to Pandas).
        
        Parameters:
        pandas_df (pd.DataFrame): Pandas DataFrame for local anomaly detection.
        contamination (float): The proportion of outliers in the data set.
        
        Returns:
        pd.DataFrame: DataFrame with anomaly scores.
        """
        from sklearn.ensemble import IsolationForest

        iso_forest = IsolationForest(contamination=contamination, random_state=42)
        pandas_df['anomaly_score'] = iso_forest.fit_predict(pandas_df[["request_count", "response_time"]])
        return pandas_df
