import datetime
from typing import List
from typing import Dict
from typing import Any

from intezer_sdk.api import IntezerApi
from intezer_sdk.api import get_global_api
from intezer_sdk.results import Results

DEFAULT_LIMIT = 100
DEFAULT_OFFSET = 0


def file_analyses_history_query(*,
                                start_date: datetime.datetime,
                                end_date: datetime.datetime,
                                api: IntezerApi = None,
                                aggregate_view: bool = None,
                                sources: List[str] = None,
                                verdicts: List[str] = None,
                                file_hash: str = None,
                                family_names: List[str] = None,
                                file_name: str = None,
                                limit: int = DEFAULT_LIMIT,
                                offset: int = DEFAULT_OFFSET
                                ) -> Results:
    """
    Query for file analyses history.
    :param start_date: Date to query from.
    :param end_date: Date to query until.
    :param api: Instance of public Intezer API for request server.
    :param aggregate_view: Should the result be aggregated by latest
    hash/url/computer.
    :param sources: Filter the analyses by its source.
    :param verdicts: Filter by the analysis's verdict
    :param file_name: Filter by the uploaded file's name
    :param family_names: Filter by the analysis's malicious family name
    :param file_hash: Filter by the file's hash, in one of the following
    formats: SHA256, SHA1 or MD5
    :param limit: Number of analyses returned by the query.
    :param offset: Number of analyses to skips the before beginning to
    return the analyses.
    :return: File query result from server as Results iterator.
    """
    filters = general_data_analyses_history(
        start_date, end_date, aggregate_view, sources, verdicts, limit, offset
    )
    if file_hash is not None:
        filters['hash'] = file_hash
    if family_names:
        filters['family_names'] = family_names
    if file_name:
        filters['file_name'] = file_name
    return Results('/analyses/history', api or get_global_api(), filters)


def endpoint_analyses_history_query(*,
                                    start_date: int,
                                    end_date: int,
                                    api: IntezerApi = None,
                                    aggregate_view: bool = None,
                                    sources: List[str] = None,
                                    verdicts: List[str] = None,
                                    limit: int = DEFAULT_LIMIT,
                                    offset: int = DEFAULT_OFFSET
                                    ) -> Results:
    """
    Query for endpoint analyses history.

    :param start_date: Date to query from.
    :param end_date: Date to query until.
    :param api: Instance of public Intezer API for request server.
    :param aggregate_view: Should the result be aggregated by latest
    hash/url/computer.
    :param sources: Filter the analyses by its source.
    :param verdicts: Filter by the analysis's verdict
    :param limit: Number of analyses returned by the query.
    :param offset: Number of analyses to skips the before beginning to
    return the analyses.
    :return: Endpoint query result from server as Results iterator.
    """
    filters = general_data_analyses_history(
        start_date, end_date, aggregate_view, sources, verdicts, limit, offset
    )
    return Results(
        '/endpoint-analyses/history',
        api or api or get_global_api(),
        filters
    )


def url_analyses_history_query(*,
                               start_date: int,
                               end_date: int,
                               api: IntezerApi = None,
                               sources: List[str] = None,
                               verdicts: List[str] = None,
                               sub_verdicts: List[str] = None,
                               did_download_file: bool = None,
                               submitted_url: str = None,
                               aggregate_view: bool = False,
                               limit: int = DEFAULT_LIMIT,
                               offset: int = DEFAULT_OFFSET
                               ) -> Results:
    """
    Query for url analyses history.

    :param start_date: Date to query from.
    :param end_date: Date to query until.
    :param api: Instance of public Intezer API for request server.
    :param sources: Filter the analyses by its source.
    :param verdicts: Filter by the analysis's verdict
    :param sub_verdicts: Filter by the analysis's verdict
    :param did_download_file: Should the result be aggregated by latest url.
    :param submitted_url: Filter by specific url
    :param aggregate_view: Should the result be aggregated by latest url.
    :param limit: Number of analyses returned by the query.
    :param offset: Number of analyses to skips the before beginning to
    return the analyses.
    :return: URL query result from server as Results iterator.
    """
    filters = general_data_analyses_history(
        start_date, end_date, aggregate_view, sources, verdicts, limit, offset
    )

    if did_download_file:
        filters['did_download_file'] = did_download_file
    if submitted_url:
        filters['submitted_url'] = submitted_url
    if sub_verdicts:
        filters['sub_verdicts'] = sub_verdicts

    return Results('/url-analyses/history', api or get_global_api(), filters)


def general_data_analyses_history(*,
                                  start_date: datetime.datetime,
                                  end_date: datetime.datetime,
                                  aggregated_view: bool = None,
                                  sources: List[str] = None,
                                  verdicts: List[str] = None,
                                  limit: int = DEFAULT_LIMIT,
                                  offset: int = DEFAULT_OFFSET
                                  ) -> Dict[str, Any]:
    data = {
        'start_date': int(start_date.timestamp()),
        'end_date': int(end_date.timestamp()),
        'limit': limit,
        'offset': offset,
    }
    if aggregated_view is not None:
        data['aggregate_view'] = aggregated_view
    if sources:
        data['sources'] = sources
    if verdicts:
        data['verdicts'] = verdicts
    return data
