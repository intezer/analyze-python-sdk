from typing import Dict
from typing import List
from typing import Tuple
from typing import Optional

from intezer_sdk.types import AlertDefinitionMapping
from intezer_sdk._api import IntezerApi
from intezer_sdk._api import IntezerApiClient
from intezer_sdk.api import get_global_api
from intezer_sdk import errors


def get_alerts_by_alert_ids(alert_ids: List[str],
                            environments: List[str] = None,
                            api: IntezerApi = None) -> Tuple[int, List[dict]]:
    """
    Get alerts by alert ids.

    :param alert_ids: list of all ids to get alerts from.
    :param environments: what environments to get alerts from.
    :param api: The API connection to Intezer.
    :return: amount of alerts sent from server and list of alerts with all details about each alert.
    """
    api = IntezerApi(api or get_global_api())
    result = api.get_alerts_by_alert_ids(alert_ids, environments)
    return result['alerts_count'], result['alerts']


class Alert:
    """
    The Alert class is used to represent an alert from the Intezer Analyze API.

    :ivar alert_id: The alert id.
    :vartype alert_id: str
    :ivar raw_alert: The raw alert data.
    :vartype raw_alert: dict
    :ivar source: The source of the alert.
    :vartype source: str
    :ivar verdict: The verdict of the alert.
    :vartype verdict: str
    :ivar family_name: The family name of the alert.
    :vartype family_name: str
    :ivar sender: The sender of the alert.
    :vartype sender: str
    """
    def __init__(self, alert_id: str, api: IntezerApiClient = None):
        """
        Create a new Alert instance with the given alert id.
        Please note that this does not query the Intezer Analyze API for the alert data, but rather creates an Alert
        instance with the given alert id.

        :param alert_id: The alert id.
        :param api: The API connection to Intezer.
        """
        self.alert_id: str = alert_id
        self._api = IntezerApi(api or get_global_api())
        self.raw_alert: Optional[Dict] = None
        self.source: Optional[str] = None
        self.verdict: Optional[str] = None
        self.family_name: Optional[str] = None
        self.sender: Optional[str] = None

    def refresh_alert(self):
        """
        Refresh the alert data from the Intezer Analyze API - overrides current data (if exists) with the new data.

        :raises intezer_sdk.errors.AlertNotFound: If the alert was not found.
        :raises intezer_sdk.errors.AlertInProgressError: If the alert is still being processed.
        """
        result = self._api.get_alerts_by_alert_ids(alert_ids=[self.alert_id])

        if result.get('alerts_count', 0) != 1:
            raise errors.AlertNotFound(f'Alert not found')
        alert = result['alerts'][0]
        if not alert.get('triage_result'):
            raise errors.AlertInProgressError()

        self.raw_alert = alert
        self.source = alert.get('source')
        self.verdict = alert.get('triage_result', {}).get('alert_verdict')
        self.family_name = alert.get('triage_result', {}).get('family_name')
        self.sender = alert.get('sender')

    def result(self) -> Dict:
        """
        Get the raw alert result, as received from Intezer Analyze API.

        :raises intezer_sdk.errors.AlertNotFound: If the alert was not found.
        :return: The raw alert dictionary.
        """
        if not self.raw_alert:
            raise errors.AlertNotFound(f'Alert not found, try refreshing the alert')
        return self.raw_alert

    @classmethod
    def from_alert_id(cls, alert_id, api: IntezerApiClient = None):
        """
        Create a new Alert instance, and fetch the alert data from the Intezer Analyze API.

        :param alert_id: The alert id.
        :param api: The API connection to Intezer.
        :raises intezer_sdk.errors.AlertNotFound: If the alert was not found.
        :raises intezer_sdk.errors.AlertInProgressError: If the alert is still being processed.
        :return: The Alert instance, with the updated alert data.
        """
        new_alert = cls(alert_id=alert_id, api=api)
        new_alert.refresh_alert()
        return new_alert

    @classmethod
    def ingest_alert(cls,
                     raw_alert: Dict,
                     alert_mapping: AlertDefinitionMapping,
                     source: str,
                     api: IntezerApiClient = None,
                     environment: Optional[str] = None,
                     display_fields: Optional[List[str]] = None,
                     default_verdict: Optional[str] = None,
                     alert_sender: Optional[str] = None,
                     ):
        """
        Send an alert for further investigation using the Intezer Analyze API.

        :param raw_alert: The raw alert data.
        :param alert_mapping: The alert mapping - defines how to map the raw alert to get relevant information.
        :param source: The source of the alert.
        :param api: The API connection to Intezer.
        :param environment: The environment of the alert.
        :param display_fields: Fields from raw alert to display in the alert's webpage.
        :param default_verdict: The default verdict to send the alert with.
        :param alert_sender: The sender of the alert.
        :raises: :class:`requests.HTTPError` if the request failed for any reason.
        :return: The Alert instance, initialized with the alert id. when the `wait` parameter is set to True, the
                 resulting alert object will be initialized with the alert triage data.
        """
        _api = IntezerApi(api or get_global_api())
        send_alert_params = dict(
            alert=raw_alert,
            definition_mapping=alert_mapping,
            alert_source=source,
            environment=environment,
            display_fields=display_fields,
            default_verdict=default_verdict,
            alert_sender=alert_sender
        )
        send_alert_params = {key: value for key, value in send_alert_params.items() if value is not None}
        alert_id = _api.send_alert(**send_alert_params)

        return cls(alert_id=alert_id, api=api)
