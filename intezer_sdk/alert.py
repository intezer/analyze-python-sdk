import datetime
from typing import Optional, List

from intezer_sdk._api import IntezerApi
from intezer_sdk._api import IntezerApiClient
from intezer_sdk.api import get_global_api


class Alert:
    def __init__(self,
                 raw_alert: dict,
                 alert_mapping: dict,
                 source: str,
                 api: IntezerApiClient = None,
                 environment: Optional[str] = None,
                 display_fields: Optional[List[str]] = None,
                 default_verdict: Optional[str] = None,
                 alert_sender: Optional[str] = None):
        self.raw_alert = raw_alert
        self.alert_mapping = alert_mapping
        self.source = source
        self.environment = environment
        self.display_fields = display_fields
        self.default_verdict = default_verdict
        self.alert_sender = alert_sender
        self._api = IntezerApi(api or get_global_api())

    def send(self, wait: bool = False, wait_timeout: Optional[datetime.timedelta] = None) -> None:
        send_alert_params = dict(
            alert=self.raw_alert,
            definition_mapping=self.alert_mapping,
            alert_source=self.source,
            environment=self.environment,
            display_fields=self.display_fields,
            default_verdict=self.default_verdict,
            alert_sender=self.alert_sender
        )
        send_alert_params = {key: value for key, value in send_alert_params.items() if value is not None}
        self._api.send_alert(**send_alert_params)

    @classmethod
    def from_alert_id(cls, alert_id: str):
        pass
