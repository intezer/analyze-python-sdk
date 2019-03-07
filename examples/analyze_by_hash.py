from intezer_sdk.analysis import Analysis
from intezer_sdk.api import IntezerApi


def analysis_by_hash_with_wait():
    file_hash = '<hash>'
    api_key = '<api_key>'
    api = IntezerApi(api_key=api_key)

    analysis = Analysis(api=api, file_hash=file_hash)
    analysis.send(wait=True)
    result = analysis.result()


def analysis_by_hash_without_wait():
    file_hash = '<hash>'
    api_key = '<api_key>'
    api = IntezerApi(api_key=api_key)

    analysis = Analysis(api=api, file_hash=file_hash)
    analysis.send()
    analysis.wait_for_completion()
    result = analysis.result()
