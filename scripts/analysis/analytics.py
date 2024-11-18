from pyspark.sql import functions as F

class LogAnalytics:
    def __init__(self, spark_session, df):
        self.spark = spark_session
        self.df = df

    def descriptive_stats(self):
        """
        Calculate descriptive statistics for response time and total requests.
        """
        return self.df.select(
            F.mean("response_time").alias("avg_response_time"),
            F.stddev("response_time").alias("stddev_response_time"),
            F.min("response_time").alias("min_response_time"),
            F.max("response_time").alias("max_response_time"),
            F.count("status_code").alias("total_requests")
        )

    def time_based_analysis(self, interval="hour"):
        """
        Analyze data based on time intervals (hour, day, or month).
        
        Parameters:
        interval (str): The time interval to group by. Options: 'hour', 'day', 'month'.
        
        Returns:
        DataFrame: Count of requests for each time interval.
        """
        if interval not in ["hour", "day", "month"]:
            raise ValueError("Invalid interval: Choose 'hour', 'day', or 'month'")
        
        time_column = interval
        return self.df.withColumn(time_column, F.date_trunc(interval, "timestamp")) \
                      .groupBy(time_column) \
                      .count() \
                      .orderBy(time_column)

    def top_n_analysis(self, column, n=10):
        """
        Retrieve the top N most common values in a specified column.
        
        Parameters:
        column (str): The column to analyze.
        n (int): The number of top values to return.
        
        Returns:
        DataFrame: Top N values in the specified column.
        """
        return self.df.groupBy(column).count().orderBy(F.desc("count")).limit(n)

    def response_time_distribution(self):
        """
        Calculate response time distribution statistics.
        
        Returns:
        DataFrame: Distribution statistics for response time.
        """
        return self.df.select(
            F.percentile_approx("response_time", 0.5).alias("median_response_time"),
            F.percentile_approx("response_time", [0.25, 0.75]).alias("iqr_response_time")
        )

    def status_code_trend(self):
        """
        Analyze trends in status codes over time.
        
        Returns:
        DataFrame: Count of each status code by day.
        """
        return self.df.withColumn("day", F.date_trunc("day", "timestamp")) \
                      .groupBy("day", "status_code") \
                      .count() \
                      .orderBy("day", "status_code")

    def common_patterns(self):
        """
        Identify the most common IP addresses, request methods, and endpoints.
        
        Returns:
        tuple: DataFrames for top IP addresses, request methods, and endpoints.
        """
        common_ips = self.top_n_analysis("ip_address", n=10)
        common_methods = self.top_n_analysis("method", n=10)
        common_endpoints = self.top_n_analysis("endpoint", n=10)
        return common_ips, common_methods, common_endpoints
