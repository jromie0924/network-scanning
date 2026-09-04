from logging.handlers import TimedRotatingFileHandler
import sys

import boto3
from capture import Capture
import config
import csv
import json
import logging
import os

from runtime import Runtime

def init_logger():
    logger = logging.getLogger(config.APP_NAME)
    logger.setLevel(config.LOGGING_LEVEL)
    
    # Create log directory if it doesn't exist
    dir = os.path.dirname(config.LOG_FILE)
    os.makedirs(dir, exist_ok=True)
    
    # Log formatter
    formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(module)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    # Stream handler (sys.stdout) for console output
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    
    # Timed rotating file handler
    # Rotates log files daily at midnight
    # Will keep 30 days of log files
    # Older log files will be automatically deleted
    file_handler = TimedRotatingFileHandler(config.LOG_FILE, when='midnight', interval=1, backupCount=30)
    file_handler.setFormatter(formatter)
    
    # Add handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

def parse_secret(secret) -> dict:
    ACCESS_KEY_ID_NAME = 'Access key ID'
    SECRET_ACCESS_KEY_NAME = 'Secret access key'
    
    secret_dict = {}
    with open(secret, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for line in reader:
            secret_dict["access_key_id"] = line[ACCESS_KEY_ID_NAME]
            secret_dict["secret_access_key"] = line[SECRET_ACCESS_KEY_NAME]
    
    return secret_dict

if __name__ == "__main__":
    init_logger()
    logger = logging.getLogger(config.APP_NAME)
    logger.info("Starting network scanner...")
    
    secret_file = config.AWS_SECRET
    secrets = parse_secret(secret_file)
    ssm_client = boto3.client("ssm",
                              aws_access_key_id=secrets["access_key_id"],
                              aws_secret_access_key=secrets["secret_access_key"],
                              region_name=config.AWS_REGION)
    
    system_mapping_parameter = ssm_client.get_parameter(Name="/network-scanning/device-map")
    system_mapping = None
    if system_mapping_parameter and system_mapping_parameter.get("Parameter"):
        system_mapping = json.loads(system_mapping_parameter.get("Parameter").get("Value"))
        # runtime = Runtime(system_mapping=system_mapping)
    
    country_blacklist_mapping_parameter = ssm_client.get_parameter(Name="/network-scanning/country-map")
    country_blacklist_mapping = None
    if country_blacklist_mapping_parameter and country_blacklist_mapping_parameter.get("Parameter"):
        country_blacklist_mapping = json.loads(country_blacklist_mapping_parameter.get("Parameter").get("Value"))
    
    runtime = Runtime(system_mapping=system_mapping, country_mapping=country_blacklist_mapping)
        
    
    capture = Capture()    
    total_packets = capture.scan()
    
    logger.info(f"Captured {total_packets} packets.")