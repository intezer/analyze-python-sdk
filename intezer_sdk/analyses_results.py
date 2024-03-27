from typing import List
from typing import Dict
from typing import Tuple

from intezer_sdk.api import IntezerApiClient
from intezer_sdk.api import raise_for_status
from intezer_sdk.history_results import HistoryResult


class AnalysesHistoryResult(HistoryResult):
    def __init__(self, request_url_path: str, api: IntezerApiClient, filters: Dict):
        """
        Fetch all analyses history results from server.
        """
        super().__init__(request_url_path, api, filters)

    def _fetch_history(self, url_path: str, data: Dict) -> Tuple[int, List]:
        """
        Request from server filtered analyses history.
        :param url_path: Url to request new data from.
        :param data: filtered data.
        :return: Count of all results exits in filtered request and amount
        analyses as requested.
        """
        response = self._api.request_with_refresh_expired_access_token(
            path=url_path, method='POST', data=data)
        raise_for_status(response)
        data_response = response.json()
        return data_response['total_count'], data_response['analyses']
