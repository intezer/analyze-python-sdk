import sys
from pprint import pprint

from intezer_sdk import api
from intezer_sdk.analysis import UrlAnalysis


def get_url_latest_analysis(url: str):
    api.set_global_api('<api-key>')
    analysis = UrlAnalysis.from_latest_analysis(url)
    pprint(analysis.result())

if __name__ == '__main__':
    get_url_latest_analysis(*sys.argv[1:])