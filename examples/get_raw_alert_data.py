import sys
from pprint import pprint

from intezer_sdk import api
from intezer_sdk.alerts import Alert


def get_raw_alert_data(alert_id: str, environment: str):
    api.set_global_api('<api_key>')

    alert = Alert(alert_id=alert_id)
    raw_data = alert.get_raw_data(environment=environment)
    pprint(f'Alert convenience method: {raw_data}')


if __name__ == '__main__':
    get_raw_alert_data(*sys.argv[1:])
