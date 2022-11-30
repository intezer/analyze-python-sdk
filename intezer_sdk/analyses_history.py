import datetime
from typing import List, Dict, Union

from intezer_sdk.api import IntezerApi
from intezer_sdk.results import Results


class AnalysesHistory:
    def __init__(self, api: IntezerApi):
        self.api = api

    def file_analyses_history(self, *,
                              start_date: int,
                              end_date: int,
                              aggregate_view: bool = None,
                              sources: List[str] = None,
                              verdicts: List[str] = None,
                              hash_data: str = None,
                              family_names: List[str] = None,
                              file_name: str = None,
                              limit: int = 100,
                              offset: int = 0
                              ):
        """
        Query for file analyses history.
        :param start_date: Date to query from.
        :param end_date: Date to query until.
        :param aggregate_view: Should the result be aggregated by latest
        hash/url/computer.
        :param sources: Filter the analyses by its source.
        :param verdicts: Filter by the analysis's verdict
        :param file_name: Filter by the uploaded file's name
        :param family_names: Filter by the analysis's malicious family name
        :param hash_data: Filter by the file's hash, in one of the following
        formats: SHA256, SHA1 or MD5
        :param limit: Number of analyses returned by the query.
        :param offset: Number of analyses to skips the before beginning to
        return the analyses.
        :return: all file history analyses.
        """
        data = self._data_analyses_history(
            start_date, end_date, aggregate_view, sources, verdicts, limit, offset
        )
        if hash_data is not None:
            data["hash"] = hash_data
        if family_names is not None:
            data["family_names"] = family_names
        if file_name is not None:
            data["file_name"] = file_name

        return Results('/analyses/history', self.api, data)

    def end_point_analyses_history(self, *,
                                   start_date: int,
                                   end_date: int,
                                   aggregate_view: bool = None,
                                   sources: List[str] = None,
                                   verdicts: List[str] = None,
                                   limit: int = 100,
                                   offset: int = 0
                                   ):
        """
        Query for endpoint analyses history.

        :param start_date: Date to query from.
        :param end_date: Date to query until.
        :param aggregate_view: Should the result be aggregated by latest
        hash/url/computer.
        :param sources: Filter the analyses by its source.
        :param verdicts: Filter by the analysis's verdict
        :param limit: Number of analyses returned by the query.
        :param offset: Number of analyses to skips the before beginning to
        return the analyses.
        :return: all endpoint history analyses.
        """
        data = self._data_analyses_history(
            start_date, end_date, aggregate_view, sources, verdicts, limit, offset
        )
        return Results('/endpoint-analyses/history', self.api, data)

    def url_analyses_history(self, *,
                             start_date: int,
                             end_date: int,
                             sources: List[str] = None,
                             verdicts: List[str] = None,
                             sub_verdicts: List[str] = None,
                             did_download_file: bool = None,
                             submitted_url: str = None,
                             aggregate_view: bool = False,
                             limit: int = 100,
                             offset: int = 0
                             ):
        """
        Query for url analyses history.

        :param start_date: Date to query from.
        :param end_date: Date to query until.
        :param sources: Filter the analyses by its source.
        :param verdicts: Filter by the analysis's verdict
        :param sub_verdicts: Filter by the analysis's verdict
        :param did_download_file: Should the result be aggregated by latest
        hash/url/computer.
        :param submitted_url: Filter by specific url
        :param aggregate_view: Should the result be aggregated by latest
        hash/url/computer.
        :param limit: Number of analyses returned by the query.
        :param offset: Number of analyses to skips the before beginning to
        return the analyses.
        :return: All url history analyses.
        """
        data = self._data_analyses_history(
            start_date, end_date, aggregate_view, sources, verdicts, limit, offset
        )

        if did_download_file:
            data["did_download_file"] = did_download_file
        if submitted_url:
            data["submitted_url"] = submitted_url
        if sub_verdicts:
            data["sub_verdicts"] = sub_verdicts

        return Results('/url-analyses/history', self.api, data)

    @staticmethod
    def _data_analyses_history(*,
                               start_date: datetime.datetime,
                               end_date: datetime.datetime,
                               aggregate_view: bool = None,
                               sources: List[str] = None,
                               verdicts: List[str] = None,
                               limit: int = 100,
                               offset: int = 0
                               ) -> Dict[str, Union[str, int, List]]:
        """
        Set common vals for analyses history api request.
        :param start_date: Date to query from.
        :param end_date: Date to query until.
        :param aggregate_view: Should the result be aggregated by latest
        hash/url/computer.
        :param sources: Filter the analyses by its source.
        :param verdicts: Filter by the analysis's verdict.
        :param limit: Number of analyses returned by the query.
        :param offset: Number of analyses to skips the before beginning to
        return the analyses.
        :return: All data to send the analyses request.
        """
        data = {
            'start_date': int(start_date.timestamp()),
            'end_date': int(end_date.timestamp()),
            'limit': limit,
            'offset': offset,
        }
        if aggregate_view is not None:
            data["aggregate_view"] = aggregate_view
        if sources is not None:
            data["sources"] = sources
        if verdicts is not None:
            data["verdicts"] = verdicts
        return data
