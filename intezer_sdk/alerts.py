from http import HTTPStatus

from intezer_sdk.api import IntezerApiClient
from intezer_sdk.api import get_global_api
from intezer_sdk.api import raise_for_status


class Alerts:
    def __init__(self, api: IntezerApiClient = None):
        """
        Query alerts from Intezer Analyze.

        :param api: Instance of Intezer API for request server.
        """
        self._api = api or get_global_api()

    def get_alerts_by_alert_ids(self, alert_ids: list[str], environments: list[str] = None) -> tuple[int, list[dict]]:
        """
        Get alerts by alert ids.

        :param alert_ids: list of all ids to get alerts from.
        :param environments: what environments to get alerts from.
        :return: amount of alerts sent from server and list of alerts with all details about each alert.
        """
        response = self._api.request_with_refresh_expired_access_token(method='GET',
                                                                       path='/alerts/search',
                                                                       data=dict(alert_ids=alert_ids,
                                                                                 environments=environments))
        raise_for_status(response, statuses_to_ignore=[HTTPStatus.BAD_REQUEST])
        data_response = response.json()
        return data_response['result']['alerts_count'], data_response['result']['alerts']
