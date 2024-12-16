from flask import Flask, jsonify, render_template, request
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import StructType, StructField, TimestampType, StringType, IntegerType, DoubleType
from datetime import datetime, timedelta
import json
import sys
import os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from scripts.analysis.anomaly_detection import AnomalyDetector

app = Flask(__name__, template_folder = "template")

spark = SparkSession.builder \
    .appName("Log Analysis Dashboard") \
    .getOrCreate()

def start_streaming_job():
    if 'streaming_query' not in globals():
        logs_df = spark.readStream \
            .format("kafka") \
            .option("kafka.bootstrap.servers", "localhost:9092") \
            .option("subscribe", "server_logs") \
            .load()

        # Define the schema for the incoming Kafka data
        log_schema = StructType([
            StructField("timestamp", TimestampType(), True),
            StructField("ip_address", StringType(), True),
            StructField("endpoint", StringType(), True),
            StructField("request_count", IntegerType(), True),
            StructField("response_time", DoubleType(), True)
        ])

        # Parse the Kafka JSON messages into a structured DataFrame
        parsed_df = logs_df.selectExpr("CAST(value AS STRING) as json") \
            .select(F.from_json("json", log_schema).alias("data")) \
            .select("data.*")

        # Process the parsed DataFrame to detect anomalies
        anomaly_detector = AnomalyDetector(spark, parsed_df)
        processed_df = anomaly_detector.detect_log_anomalies()

        global streaming_query
        streaming_query = processed_df.writeStream \
            .format("memory") \
            .queryName("anomalies") \
            .option("checkpointLocation", "/tmp/checkpoints/app_streaming") \
            .start()

CLEANED_LOGS_PATH = "/data/cleaned_logs/"

@app.route('/')
def dashboard():
    """Render the main dashboard page"""
    return render_template('index.html')

@app.route('/analysis/stats/overview')
def get_overview_stats():
    """Get overview statistics"""
    try:
        df = spark.read.parquet(CLEANED_LOGS_PATH)
        
        # Calculate basic stats
        stats = df.agg(
            F.count("*").alias("total_requests"),
            F.avg("response_time").alias("avg_response_time"),
            F.max("response_time").alias("max_response_time"),
            F.countDistinct("ip_address").alias("unique_visitors"),
            F.avg("response_size").alias("avg_response_size")
        ).collect()[0]
        
        return jsonify({
            "total_requests": int(stats["total_requests"]),
            "avg_response_time": round(float(stats["avg_response_time"]), 2),
            "max_response_time": int(stats["max_response_time"]),
            "unique_visitors": int(stats["unique_visitors"]),
            "avg_response_size": round(float(stats["avg_response_size"]), 2)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/analysis/stats/hourly')
def get_hourly_stats():
    """Get hourly request distribution"""
    try:
        df = spark.read.parquet(CLEANED_LOGS_PATH)
        
        hourly_stats = df.withColumn(
            "hour", F.hour("timestamp")
        ).groupBy("hour").agg(
            F.count("*").alias("requests"),
            F.avg("response_time").alias("avg_response_time")
        ).orderBy("hour").collect()
        
        return jsonify([{
            "hour": row["hour"],
            "requests": int(row["requests"]),
            "avg_response_time": round(float(row["avg_response_time"]), 2)
        } for row in hourly_stats])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/analysis/stats/status')
def get_status_stats():
    """Get status code distribution"""
    try:
        df = spark.read.parquet(CLEANED_LOGS_PATH)
        
        status_stats = df.groupBy("status_code").count().collect()
        
        return jsonify([{
            "status_code": row["status_code"],
            "count": int(row["count"])
        } for row in status_stats])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/analysis/stats/top_endpoints')
def get_top_endpoints():
    """Get top requested endpoints"""
    try:
        df = spark.read.parquet(CLEANED_LOGS_PATH)
        
        top_endpoints = df.groupBy("endpoint") \
            .agg(
                F.count("*").alias("requests"),
                F.avg("response_time").alias("avg_response_time")
            ) \
            .orderBy(F.desc("requests")) \
            .limit(10) \
            .collect()
        
        return jsonify([{
            "endpoint": row["endpoint"],
            "requests": int(row["requests"]),
            "avg_response_time": round(float(row["avg_response_time"]), 2)
        } for row in top_endpoints])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/analysis/anomalies')
def detect_anomalies():
    """Detect and return log anomalies using cleaned logs"""
    try:
        df = spark.read.parquet(CLEANED_LOGS_PATH)
        
        anomaly_detector = AnomalyDetector(spark_df=df)
        
        anomalies_result = anomaly_detector.detect_log_anomalies()
        
        if isinstance(anomalies_result, spark.sql.dataframe.DataFrame):
            anomalies = anomalies_result.toPandas().to_dict(orient="records")
            total_anomalies = len(anomalies)
        elif isinstance(anomalies_result, dict):
            anomalies = anomalies_result
            total_anomalies = sum(len(v) for v in anomalies.values() if isinstance(v, list))
        else:
            raise TypeError("Unsupported return type from detect_log_anomalies: "
                            f"{type(anomalies_result)}")
        
        return jsonify({
            "total_anomalies": total_anomalies,
            "anomalies": anomalies
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
