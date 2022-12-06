import datetime

from intezer_sdk.analyses_history import query_file_analyses_history


def analyses_history_example():
    results = query_file_analyses_history(
        start_date=datetime.datetime.now() - datetime.timedelta(days=3),
        end_date=datetime.datetime.now()
    )

    for result in results:
        print(result)

    # or:
    all_results = list(results)
    for result in all_results:
        print(result)

