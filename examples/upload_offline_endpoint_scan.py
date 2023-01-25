import sys
from pprint import pprint

from intezer_sdk import api
from intezer_sdk.endpoint_analysis import EndpointAnalysis


def send_file_with_wait(metadata_dir: str):
    api.set_global_api('api-key')
    analysis = EndpointAnalysis(metadata_dir=metadata_dir)
    analysis.send(wait=True)
    pprint(analysis.result())

if __name__ == '__main__':
    send_file_with_wait(*sys.argv[1:])
