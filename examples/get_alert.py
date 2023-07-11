import sys
from pprint import pprint

from intezer_sdk import api
from intezer_sdk.alerts import Alert


def get_alert_by_id(alert_id: str):
    api.set_global_api('<api_key>')

    alert = Alert.from_id(alert_id=alert_id,
                          fetch_scans=False,
                          wait=False)
    pprint(alert)


if __name__ == '__main__':
    get_alert_by_id(*sys.argv[1:])
