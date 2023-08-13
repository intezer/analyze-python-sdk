import io
import sys
from pprint import pprint

from intezer_sdk import api
from intezer_sdk.analysis import FileAnalysis


def send_file_with_wait(file_path):
    api.set_global_api('<api_key>')
    analysis = FileAnalysis(file_path=file_path)
    analysis.send(wait=True)
    pprint(analysis.result())


def send_file_without_wait():
    api.set_global_api('2d0caeb6-b5e0-4d36-b8fd-13b5ac4e39f4')
    analysis = FileAnalysis(file_stream=io.BytesIO(b'dsadsagt432'), file_name='123')
    analysis.send()
    try:
        data = FileAnalysis.from_latest_hash_analysis('71e0b5e3a3b40b1904bb0fbb412ef7735484efa1c53c946e155f3e6970a1aa71')
    except Exception as e:
        print(e)
    pprint(data)


if __name__ == '__main__':
    send_file_without_wait()
