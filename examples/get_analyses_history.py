import datetime
import sys
from pprint import pprint

from intezer_sdk.analyses_history import query_file_analyses_history
from intezer_sdk import api


def analyses_history_example(start_date: datetime.datetime, end_date: datetime.datetime):
    results = query_file_analyses_history(start_date=start_date, end_date=end_date)
    for result in results:
        pprint(result)


def main(args):
    api.set_global_api('<api_key>')
    analyses_history_example(args)


if __name__ == '__main__':
    main(sys.argv[1:])
