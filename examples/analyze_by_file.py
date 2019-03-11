import sys
from pprint import pprint

from intezer_sdk.analysis import Analysis
from intezer_sdk.api import IntezerApi


def send_file_with_wait(file_path, dynamic_unpacking=None, static_unpacking=None):
    api = IntezerApi()
    analysis = Analysis(api=api,
                        file_path=file_path,
                        dynamic_unpacking=dynamic_unpacking,
                        static_unpacking=static_unpacking)
    analysis.send(wait=True)
    pprint(analysis.result())


def send_file_without_wait(file_path, dynamic_unpacking, static_unpacking):
    api = IntezerApi()
    analysis = Analysis(api=api,
                        file_path=file_path,
                        dynamic_unpacking=dynamic_unpacking,
                        static_unpacking=static_unpacking)
    analysis.send()
    analysis.wait_for_completion()
    pprint(analysis.result())


if __name__ == '__main__':
    send_file_with_wait(*sys.argv[1:])
