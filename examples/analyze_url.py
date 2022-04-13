import sys
from pprint import pprint

from intezer_sdk import api
from intezer_sdk.analysis import UrlAnalysis


def send_file_with_wait(url):
    api.set_global_api('<api_key>')
    analysis = UrlAnalysis(url=url)
    analysis.send(wait=True)
    pprint(analysis.result())


def send_file_without_wait(url):
    api.set_global_api('<api_key>')
    analysis = UrlAnalysis(url=url)
    analysis.send()
    analysis.wait_for_completion()
    pprint(analysis.result())


if __name__ == '__main__':
    send_file_with_wait(*sys.argv[1:])
