from pprint import pprint

from intezer_sdk import api
from intezer_sdk.analysis import UrlAnalysis


def get_url_latest_analysis(url: str):
    api.set_global_api('519643d2-f373-40c1-9616-d4650c4741ee')
    analysis = UrlAnalysis.from_latest_analysis(url)
    pprint(analysis.result())

if __name__ == '__main__':
    get_url_latest_analysis('https://www.google.com/')