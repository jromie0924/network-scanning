import boto3
from capture import Capture
import config
import csv
import json

from runtime import Runtime


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
    
    print(f"Captured {total_packets} packets.")