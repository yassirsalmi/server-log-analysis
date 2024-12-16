import pandas as pd
from datetime import datetime
import json
import os
import re

class WebLogAnomalyDetector:
    def __init__(self, spark_df=None, log_file_path=None):
        """
        Initialize the anomaly detector with either a Spark DataFrame or log file path
        
        Args:
            spark_df (pyspark.sql.DataFrame, optional): Spark DataFrame of logs
            log_file_path (str, optional): Path to log file
        """
        self.spark_df = spark_df
        self.log_file_path = log_file_path
        self.logs_df = None
        
        self.config = {
            'suspicious_status_codes': [401, 403, 500, 502, 503],
            'suspicious_http_methods': ['DELETE', 'PUT'],
            'max_requests_per_ip': 100,
            'max_response_time_ms': 5000,
            'unusual_user_agents': ['sqlmap', 'nikto', 'nmap'],
            'geoblocking_countries': [] 
        }
    
    def parse_spark_logs(self):
        """
        Convert Spark DataFrame to Pandas DataFrame for analysis
        """
        if self.spark_df is None:
            raise ValueError("No Spark DataFrame provided")
        
        logs_pdf = self.spark_df.toPandas()
        
        column_mapping = {
            'ip_address': 'ip',
        }
        
        logs_pdf = logs_pdf.rename(columns=column_mapping)
        
        self.logs_df = logs_pdf
        return self.logs_df
    
    def detect_anomalies(self):
        """
        Detect anomalies in the log data
        
        Returns:
            dict: Dictionary of anomalies across different categories
        """
        if self.logs_df is None:
            if self.spark_df is not None:
                print("Spark DataFrame columns:", self.spark_df.columns)
                self.parse_spark_logs()
                print("Parsed DataFrame columns:", self.logs_df.columns)
            elif self.log_file_path:
                self.parse_logs()
            else:
                raise ValueError("No log data provided")
        
        anomalies = {
            'status_code_anomalies': self.detect_status_code_anomalies(),
            'method_anomalies': self.detect_method_anomalies(),
            'user_agent_anomalies': self.detect_user_agent_anomalies(),
            'ip_anomalies': self.detect_ip_anomalies(),
            'performance_anomalies': self.detect_performance_anomalies(),
            'security_anomalies': self.detect_security_anomalies()
        }
        return anomalies

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
        suspicious_status_logs = self.logs_df[
            self.logs_df['status_code'].isin(self.config['suspicious_status_codes'])
        ]
        return [{
            'type': 'Suspicious Status Code',
            'ip': row.get('ip') or row.get('ip_address', 'Unknown'),
            'status_code': row['status_code'],
            'endpoint': row['endpoint'],
            'timestamp': row['timestamp'].isoformat() if pd.notna(row['timestamp']) else 'Unknown'
        } for _, row in suspicious_status_logs.iterrows()]

    def detect_method_anomalies(self):
        suspicious_method_logs = self.logs_df[
            self.logs_df['method'].isin(self.config['suspicious_http_methods'])
        ]
        return [{
            'type': 'Suspicious HTTP Method',
            'ip': row.get('ip') or row.get('ip_address', 'Unknown'),
            'method': row['method'],
            'endpoint': row['endpoint'],
            'timestamp': row['timestamp'].isoformat() if pd.notna(row['timestamp']) else 'Unknown'
        } for _, row in suspicious_method_logs.iterrows()]

    def detect_user_agent_anomalies(self):
        unusual_ua_logs = self.logs_df[
            self.logs_df['user_agent'].str.contains('|'.join(self.config['unusual_user_agents']), case=False, na=False)
        ]
        return [{
            'type': 'Unusual User Agent',
            'ip': row.get('ip') or row.get('ip_address', 'Unknown'),
            'user_agent': row['user_agent'],
            'endpoint': row['endpoint'],
            'timestamp': row['timestamp'].isoformat() if pd.notna(row['timestamp']) else 'Unknown'
        } for _, row in unusual_ua_logs.iterrows()]

    def detect_ip_anomalies(self):
        ip_column = 'ip' if 'ip' in self.logs_df.columns else 'ip_address'
        ip_request_counts = self.logs_df[ip_column].value_counts()
        high_traffic_ips = ip_request_counts[ip_request_counts > self.config['max_requests_per_ip']]
        return [{
            'type': 'High Request Rate',
            'ip': ip,
            'request_count': int(count),
            'max_allowed_requests': self.config['max_requests_per_ip']
        } for ip, count in high_traffic_ips.items()]

    def detect_performance_anomalies(self):
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
        security_anomalies = []
        
        malicious_ua_logs = self.logs_df[
            self.logs_df['user_agent'].str.contains('|'.join(self.config['unusual_user_agents']), case=False, na=False)
        ]
        
        if not malicious_ua_logs.empty:
            security_anomalies.append({
                'type': 'suspicious_user_agents',
                'details': malicious_ua_logs['user_agent'].value_counts().to_dict()
            })
        
        unauthorized_logs = self.logs_df[self.logs_df['status_code'] == 401]
        if not unauthorized_logs.empty:
            security_anomalies.append({
                'type': 'unauthorized_access',
                'count': len(unauthorized_logs),
                'endpoints': unauthorized_logs['endpoint'].value_counts().to_dict()
            })
        
        return security_anomalies