import logging
import sys
from pprint import pprint

from intezer_sdk import api
from intezer_sdk.endpoint_analysis import EndpointAnalysis


def send_file_with_wait(metadata_dir: str):
    api.set_global_api('02d88a2a-b896-4381-808f-b872666bb2c5')
    analysis = EndpointAnalysis(metadata_dir=metadata_dir)
    analysis.send(wait=True)
    pprint(analysis.result())

if __name__ == '__main__':
    metadata_dir = "/mnt/c/Users/itamar/Downloads/scans/8ee86f33-d595-4616-96c9-e422c40418a0"
    send_file_with_wait(metadata_dir)
