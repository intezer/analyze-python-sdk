from intezer_sdk.analysis import Analysis
from intezer_sdk.api import IntezerApi


def send_file_with_wait():
    file_path = '<file_path>'
    dynamic_unpacking = '<Boolean>'
    api_key = '<api_key>'
    api = IntezerApi(api_key=api_key)

    analysis = Analysis(api=api, file_path=file_path, dynamic_unpacking=dynamic_unpacking)
    analysis.send(wait=True)
    result = analysis.result()


def send_file_without_wait():
    file_path = '<file_path>'
    dynamic_unpacking = '<Boolean>'
    api_key = '<api_key>'
    api = IntezerApi(api_key=api_key)

    analysis = Analysis(api=api, file_path=file_path, dynamic_unpacking=dynamic_unpacking)
    analysis.send()
    analysis.wait_for_completion()
    result = analysis.result()
