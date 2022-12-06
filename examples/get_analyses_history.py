import datetime
import sys

from intezer_sdk.analyses_history import query_file_analyses_history


def analyses_history_example(start_date: datetime.datetime, end_date: datetime.datetime):
    results = query_file_analyses_history(
        start_date=start_date,
        end_date=end_date,

    )

    for result in results:
        print(result)

    # or:
    all_results = list(results)
    for result in all_results:
        print(result)


def main(args):
    analyses_history_example(args)


if __name__ == '__main__':
    main(sys.argv[1:])
