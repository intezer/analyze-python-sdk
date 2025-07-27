from typing import List
from typing import Literal
from typing import Tuple

from intezer_sdk.api import IntezerApiClient
from intezer_sdk.api import raise_for_status
from intezer_sdk.history_results import HistoryResult


class DevicesHistoryResult(HistoryResult):

    def __init__(self,
                 request_url_path: str,
                 api: IntezerApiClient,
                 filters: dict,
                 search_mode: Literal['and', 'or'] = 'and'):
        """
        Fetch all alerts history results from server.
        """
        super().__init__(request_url_path, api, filters)
        self._search_mode = search_mode

    def _fetch_history(self, url_path: str, data: dict) -> Tuple[int, List]:
        """
        Request devices from server according to filters.
        :param url_path: Url to request new data from.
        :param data: Filters data.
        :return: Count of all results in filtered request and the devices themselves.
        """
        data['search_mode'] = self._search_mode
        response = self._api.request_with_refresh_expired_access_token(
            path=url_path, method='POST', data=data)
        raise_for_status(response)
        data_response = response.json()
        return data_response['devices_count'], data_response['devices']
