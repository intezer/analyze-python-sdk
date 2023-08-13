import sys
from pprint import pprint

from intezer_sdk import api
from intezer_sdk.analysis import FileAnalysis


def send_file_with_wait(file_path):
    api.set_global_api('<api_key>')
    analysis = FileAnalysis(file_path=file_path)
    analysis.send(wait=True)
    pprint(analysis.result())


def send_file_without_wait(file_path):
    api.set_global_api('<api_key>')
    analysis = FileAnalysis(file_path=file_path)
    analysis.send()
    analysis.wait_for_completion()
    pprint(analysis.result())


if __name__ == '__main__':
    send_file_with_wait(*sys.argv[1:])
