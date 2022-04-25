import datetime
import sys
from pprint import pprint

from intezer_sdk import api
from intezer_sdk.analysis import FileAnalysis


def analysis_by_hash_with_wait(file_hash: str):
    api.set_global_api('<api_key>')
    analysis = FileAnalysis(file_hash=file_hash)
    analysis.send(wait=True)
    pprint(analysis.result())


def analysis_by_hash_with_wait_timeout(file_hash: str):
    api.set_global_api('<api_key>')
    analysis = FileAnalysis(file_hash=file_hash)
    analysis.send(wait=True, wait_timeout=datetime.timedelta(minutes=1))
    pprint(analysis.result())


def analysis_by_hash_without_wait(file_hash: str):
    api.set_global_api('<api_key>')
    analysis = FileAnalysis(file_hash=file_hash)
    analysis.send()
    analysis.wait_for_completion()
    pprint(analysis.result())


def get_latest_analysis_by_hash(file_hash: str):
    api.set_global_api('<api_key>')
    analysis = FileAnalysis.from_latest_hash_analysis(file_hash=file_hash)
    pprint(analysis.result())


if __name__ == '__main__':
    analysis_by_hash_with_wait(*sys.argv[1:])
