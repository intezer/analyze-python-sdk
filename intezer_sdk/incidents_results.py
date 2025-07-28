from typing import Dict
from typing import List
from typing import Tuple

from intezer_sdk.api import IntezerApiClient
from intezer_sdk.api import raise_for_status
from intezer_sdk.history_results import HistoryResult


class IncidentsHistoryResult(HistoryResult):

    def __init__(self, request_url_path: str, api: IntezerApiClient, filters: dict):
        """
        Fetch all alerts history results from server.
        """
        super().__init__(request_url_path, api, filters)

    def _fetch_history(self, url_path: str, data: dict) -> Tuple[int, list]:
        """
        Request incidents from server according to filters.
        :param url_path: Url to request new data from.
        :param data: Filters data.
        :return: Count of all results in filtered request and the incidents themselves.
        """
        response = self._api.request_with_refresh_expired_access_token(
            path=url_path, method='POST', data=data)
        raise_for_status(response)
        data_response = response.json()['result']
        return data_response['incidents_count'], data_response['incidents']
