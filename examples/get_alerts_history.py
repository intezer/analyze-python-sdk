import datetime
import sys
from pprint import pprint

from intezer_sdk.alerts import query_alerts_history
from intezer_sdk import api


def alerts_history_example(start_date: datetime.datetime, end_date: datetime.datetime):
    results = query_alerts_history(start_time=start_date, end_time=end_date)
    for result in results:
        pprint(result)


def main(args):
    api.set_global_api('<api_key>')
    alerts_history_example(**args)


if __name__ == '__main__':
    main(sys.argv[1:])