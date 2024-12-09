#!/bin/bash

# Server Log Analysis Project - Startup Script

source server-log-analysis/server-analysis-env/bin/activate

kill_port() {
    local port=$1
    local pid=$(lsof -ti:$port)
    if [ ! -z "$pid" ]; then
        echo "Killing process on port $port"
        kill -9 $pid
    fi
}

start_kafka() {
    echo "Starting Kafka services..."
    cd ~/kafka
    bin/zookeeper-server-start.sh -daemon config/zookeeper.properties
    bin/kafka-server-start.sh -daemon config/server.properties
}

start_hadoop() {
    echo "Starting Hadoop services..."
    start-all.sh
}

start_kafka_producer() {
    cd /home/yassir/Desktop/workspace/server-log-analysis/
    nohup python3 scripts/kafka_producer.py > kafka_producer.log 2>&1 &
}

start_main_processing() {
    cd /home/yassir/Desktop/workspace/server-log-analysis/
    export PYSPARK_SUBMIT_ARGS="--packages org.apache.spark:spark-streaming-kafka-0-10_2.12:3.2.0,org.apache.spark:spark-sql-kafka-0-10_2.12:3.2.0 pyspark-shell"
    nohup python3 scripts/main.py > main_processing.log 2>&1 &
}

start_web_app() {
    kill_port 5000
    cd /home/yassir/Desktop/workspace/server-log-analysis/
    python3 web/app.py
}

main() {
    start_kafka
    start_hadoop
    sleep 15

    start_kafka_producer
    sleep 5
    start_main_processing
    sleep 3
    start_web_app
}

main
