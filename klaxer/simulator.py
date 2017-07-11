"""Simulate alerts!

Usage: python -m klaxer.simulator
"""

import argparse
import json
import random
import sys

import requests

SEVERITIES = ['warning', 'error']

SYSTEM = 'service.example.com'
SERVICE_NAME = 'Service'

MESSAGE_TEMPLATE = {
    'channel': '#apitests',
    'username': 'sensu',
    'icon_emoji': ':skull:',
    'attachments': [{
    }]
}

def send_alert(host, severity, debug):
    sys.stdout.write(f'Sending {severity}... ')
    MESSAGE_TEMPLATE['attachments'][0] = {
        'title': f'{SYSTEM} - {severity}',
        'text': f'{SERVICE_NAME}/disk-usage: CheckDisk {severity.upper()}: / 85.12% bytes usage (6 GiB/7 GiB)\n : {SYSTEM} : sensu-clients,testing,client:{SERVICE_NAME}',
        'color': f'{"red" if severity == "error" else "yellow"}',
    }
    if debug:
        response = requests.post(f'http://{host}/alert/sensu/12345?debug=true', json=MESSAGE_TEMPLATE)
    else:
        response = requests.post(f'http://{host}/alert/sensu/12345', json=MESSAGE_TEMPLATE)
    sys.stdout.write(f'{response.text}\n')

def main():
    args = parse_args()
    for _ in range(args.n):
        severity = random.choice(SEVERITIES) if args.severity == 'both' else args.severity
        send_alert(args.host, severity, args.debug)

def parse_args():
    parser = argparse.ArgumentParser(description='Send some requests')
    parser.add_argument('-n', default=1, type=int, help='Number of messages to send')
    parser.add_argument('-s', dest='severity', default='both', choices=['both'] + SEVERITIES, help='Severity of messages to send')
    parser.add_argument('--host', default='localhost:8000', help='Host to send messages to')
    parser.add_argument('-d', dest='debug', default=False, action='store_true', help='Debug mode')
    return parser.parse_args()

if __name__ == "__main__":
    main()
