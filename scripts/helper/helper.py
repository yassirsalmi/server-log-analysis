from pyspark.sql import SparkSession

class SparkSessionBuilder:
    """
    Helper class to create and configure a Spark session.
    """
    @staticmethod
    def create(app_name: str = "serverLogsAnalysis") -> SparkSession:
        spark = SparkSession.builder \
            .appName(app_name) \
            .config("spark.sql.legacy.timeParserPolicy", "LEGACY") \
            .getOrCreate()
        spark.sparkContext.setLogLevel("ERROR")
        return spark