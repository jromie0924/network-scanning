import os


AWS_SECRET = f'{os.environ.get("HOME", "/home/jackson")}/.aws_secret/network_scanner_app_accessKeys.csv'
AWS_REGION = "us-east-2"

SCANNING_INTERFACE = "eth0"

NAUGHTY_LIST = "device_naughty_list.json"