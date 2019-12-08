import sys
from pprint import pprint

from intezer_sdk import api
from intezer_sdk.analysis import Analysis


def analysis_by_hash_with_wait(file_hash):  # type: (str) -> None
    api.set_global_api('<api_key>')
    analysis = Analysis(file_hash=file_hash)
    analysis.send(wait=True)
    pprint(analysis.result())


def analysis_by_hash_without_wait(file_hash):  # type: (str) -> None
    api.set_global_api('<api_key>')
    analysis = Analysis(file_hash=file_hash)
    analysis.send()
    analysis.wait_for_completion()
    pprint(analysis.result())


if __name__ == '__main__':
    analysis_by_hash_with_wait(*sys.argv[1:])
