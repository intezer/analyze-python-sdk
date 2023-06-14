from typing import Dict
from typing import List
from typing import Tuple

from intezer_sdk._api import IntezerApi
from intezer_sdk.api import get_global_api


def get_alerts_by_alert_ids(alert_ids: List[str],
                            environments: List[str] = None,
                            api: IntezerApi = None) -> Tuple[int, List[Dict]]:
    """
    Get alerts by alert ids.

    :param alert_ids: list of all ids to get alerts from.
    :param environments: what environments to get alerts from.
    :param api: The API connection to Intezer.
    :return: amount of alerts sent from server and list of alerts with all details about each alert.
    """
    api = api or get_global_api()
    return api.get_alerts_by_alert_ids(alert_ids, environments)
