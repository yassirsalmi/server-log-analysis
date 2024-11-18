import time
import random
from kafka import KafkaProducer

def produce_logs(log_file_path, kafka_topic, bootstrap_servers):
    producer = KafkaProducer(bootstrap_servers=bootstrap_servers)

    try:
        with open(log_file_path, 'r') as log_file:
            for line in log_file:
                producer.send(kafka_topic, value=line.encode('utf-8'))
                print(f"Sent log: {line.strip()}")
                time.sleep(0.1)  # to control the flow of logs
        producer.flush() 
        print("Finished sending logs")
    except KeyboardInterrupt:
        print("Process interrupted by user")
    except Exception as e:
        print(f"Error while sending logs: {e}")
    finally:
        producer.close()

if __name__ == "__main__":
    log_file_path = "./data/server_logs/logfiles.log"
    kafka_topic = "server_logs"
    kafka_servers = ["localhost:9092"]
    produce_logs(log_file_path, kafka_topic, kafka_servers)