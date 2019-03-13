import sys
from pprint import pprint

from intezer_sdk import api
from intezer_sdk.analysis import Analysis


def send_file_with_wait(file_path, dynamic_unpacking=None, static_unpacking=None):
    api.set_global_api('<api_key>')
    analysis = Analysis(file_path=file_path,
                        dynamic_unpacking=dynamic_unpacking,
                        static_unpacking=static_unpacking)
    analysis.send(wait=True)
    pprint(analysis.result())


def send_file_without_wait(file_path, dynamic_unpacking, static_unpacking):
    api.set_global_api('<api_key>')
    analysis = Analysis(file_path=file_path,
                        dynamic_unpacking=dynamic_unpacking,
                        static_unpacking=static_unpacking)
    analysis.send()
    analysis.wait_for_completion()
    pprint(analysis.result())


if __name__ == '__main__':
    send_file_with_wait(*sys.argv[1:])
