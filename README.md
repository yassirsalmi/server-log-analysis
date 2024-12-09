# Server Log Analysis Project

## Overview
This project is a comprehensive server log analysis system that leverages Apache Spark, Kafka, and geolocation data to process, clean, and analyze server logs in real-time.

## Features
- Real-time log ingestion from Kafka
- Log data cleaning and validation
- Geolocation enrichment
- processing with Apache Spark

## Prerequisites
- Python 3.8+
- Java 8 or higher
- Apache Kafka
- Apache Spark
- Apache Hadoop
- GeoLite2 City database

## Installation

### 1. Install Java

### 2. Install Apache Kafka

### 3. Install Apache Spark

### 4. Install Apache Hadoop

## Clone the Repository
```bash
git clone https://github.com/yassirsalmi/server-log-analysis.git
cd server-log-analysis
```

### 1. Create Virtual Environment
```bash
python3 -m venv server-analysis-env
source server-analysis-env/bin/activate
```

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Geolocation Database
- Download GeoLite2 City database from MaxMind
- Place the database in `GeoLite_data/GeoLite2-City.mmdb`

## Configuration
Modify the following parameters in `scripts/main.py`:
- `kafka_bootstrap_servers`: Kafka broker address
- `kafka_topic`: Kafka topic for log ingestion
- `hdfs_output_path`: Output path for cleaned logs
- `geoip_db_path`: Path to GeoLite2 City database

## Running the Project
```bash
./startup.sh
```

This script will:
- Start Kafka and Zookeeper services
- Start Hadoop services
- Launch Kafka producer
- Start main log processing
- Initialize web application

## Project Structure
- `scripts/`: Core processing scripts
  - `main.py`: Main entry point
  - `kafka_producer.py`: Kafka log producer
- `processing/`: Data cleaning modules
- `analysis/`: Log analytics and anomaly detection
- `helper/`: Utility functions
- `web/`: Web interface components
- `data/`: Processed log data storage
- `GeoLite_data/`: Geolocation database

## Key Technologies
- Apache Spark
- Apache Kafka
- Python
- Geolocation Analysis
- Streaming Data Processing
