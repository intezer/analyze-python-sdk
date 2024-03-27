import datetime
from typing import Any
from typing import Dict
from typing import List

from intezer_sdk.analyses_results import AnalysesHistoryResult
from intezer_sdk.api import IntezerApiClient
from intezer_sdk.api import get_global_api
from intezer_sdk.util import add_filter

DEFAULT_LIMIT = 100
DEFAULT_OFFSET = 0
FILE_ANALYSES_REQUEST = '/analyses/history'
URL_ANALYSES_REQUEST = '/url-analyses/history'
ENDPOINT_ANALYSES_REQUEST = '/endpoint-analyses/history'


def query_file_analyses_history(*,
                                start_date: datetime.datetime,
                                end_date: datetime.datetime,
                                api: IntezerApiClient = None,
                                aggregated_view: bool = None,
                                sources: List[str] = None,
                                verdicts: List[str] = None,
                                file_hash: str = None,
                                family_names: List[str] = None,
                                file_name: str = None,
                                limit: int = DEFAULT_LIMIT,
                                offset: int = DEFAULT_OFFSET
                                ) -> AnalysesHistoryResult:
    """
    Query for file analyses history.

    :param start_date: Date to query from.
    :param end_date: Date to query until.
    :param api: Instance of Intezer API for request server.
    :param aggregated_view: Should the result be aggregated by latest hash.
    :param sources: Filter the analyses by its source.
    :param verdicts: Filter by the analysis's verdict
    :param file_name: Filter by the uploaded file's name
    :param family_names: Filter by the analysis's malicious family name
    :param file_hash: Filter by the file's hash, in one of the following formats: SHA256, SHA1 or MD5
    :param limit: Number of analyses returned by the query.
    :param offset: Number of analyses to skips the before beginning to return the analyses.
    :return: File query result from server as Results iterator.
    """
    api = api or get_global_api()
    api.assert_on_premise_above_v22_10()
    filters = generate_analyses_history_filter(
        start_date=start_date,
        end_date=end_date,
        aggregated_view=aggregated_view,
        sources=sources,
        verdicts=verdicts,
        limit=limit,
        offset=offset
    )
    add_filter(filters, 'hash', file_hash)
    add_filter(filters, 'family_names', family_names)
    add_filter(filters, 'file_name', file_name)
    return AnalysesHistoryResult(FILE_ANALYSES_REQUEST, api, filters)


def query_endpoint_analyses_history(*,
                                    start_date: datetime.datetime,
                                    end_date: datetime.datetime,
                                    api: IntezerApiClient = None,
                                    aggregated_view: bool = None,
                                    sources: List[str] = None,
                                    verdicts: List[str] = None,
                                    computer_names: List[str] = None,
                                    limit: int = DEFAULT_LIMIT,
                                    offset: int = DEFAULT_OFFSET
                                    ) -> AnalysesHistoryResult:
    """
    Query for endpoint analyses history.

    :param start_date: Date to query from.
    :param end_date: Date to query until.
    :param api: Instance of Intezer API for request server.
    :param aggregated_view: Should the result be aggregated by latest computer.
    :param sources: Filter the analyses by its source.
    :param verdicts: Filter by the analysis's verdict
    :param computer_names: Filter by computer names
    :param limit: Number of analyses returned by the query.
    :param offset: Number of analyses to skips the before beginning to return the analyses.
    :return: Endpoint query result from server as Results iterator.
    """
    api = api or get_global_api()
    api.assert_on_premise_above_v22_10()
    filters = generate_analyses_history_filter(
        start_date=start_date,
        end_date=end_date,
        aggregated_view=aggregated_view,
        sources=sources,
        verdicts=verdicts,
        computer_names=computer_names,
        limit=limit,
        offset=offset
    )
    return AnalysesHistoryResult(ENDPOINT_ANALYSES_REQUEST, api, filters)


def query_url_analyses_history(*,
                               start_date: datetime.datetime,
                               end_date: datetime.datetime,
                               api: IntezerApiClient = None,
                               sources: List[str] = None,
                               verdicts: List[str] = None,
                               sub_verdicts: List[str] = None,
                               did_download_file: bool = None,
                               submitted_url: str = None,
                               aggregated_view: bool = False,
                               limit: int = DEFAULT_LIMIT,
                               offset: int = DEFAULT_OFFSET
                               ) -> AnalysesHistoryResult:
    """
    Query for url analyses history.

    :param start_date: Date to query from.
    :param end_date: Date to query until.
    :param api: Instance of Intezer API for request server.
    :param sources: Filter the analyses by its source.
    :param verdicts: Filter by the analysis's verdict
    :param sub_verdicts: Filter by the analysis's verdict
    :param did_download_file: Should the result be aggregated by latest url.
    :param submitted_url: Filter by specific url
    :param aggregated_view: Should the result be aggregated by latest url.
    :param limit: Number of analyses returned by the query.
    :param offset: Number of analyses to skips the before beginning to return the analyses.
    :return: URL query result from server as Results iterator.
    """
    api = api or get_global_api()
    api.assert_any_on_premise()
    filters = generate_analyses_history_filter(
        start_date=start_date,
        end_date=end_date,
        aggregated_view=aggregated_view,
        sources=sources,
        verdicts=verdicts,
        limit=limit,
        offset=offset
    )
    add_filter(filters, 'did_download_file', did_download_file)
    add_filter(filters, 'submitted_url', submitted_url)
    add_filter(filters, 'sub_verdicts', sub_verdicts)

    return AnalysesHistoryResult(URL_ANALYSES_REQUEST, api, filters)


def generate_analyses_history_filter(*,
                                     start_date: datetime.datetime,
                                     end_date: datetime.datetime,
                                     aggregated_view: bool = None,
                                     sources: List[str] = None,
                                     verdicts: List[str] = None,
                                     computer_names: List[str] = None,
                                     limit: int = DEFAULT_LIMIT,
                                     offset: int = DEFAULT_OFFSET
                                     ) -> Dict[str, Any]:
    base_filter = {
        'start_date': int(start_date.timestamp()),
        'end_date': int(end_date.timestamp()),
        'limit': limit,
        'offset': offset
    }
    add_filter(base_filter, 'aggregated_view', aggregated_view)
    add_filter(base_filter, 'sources', sources)
    add_filter(base_filter, 'verdicts', verdicts)
    add_filter(base_filter, 'computer_names', computer_names)
    return base_filter
