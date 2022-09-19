import sys

from pprint import pprint
from typing import List

from intezer_sdk import api


def get_edr_alert_id_assessments(edr_alert_ids: List[str]):
    api.set_global_api('<api_key>')
    api_ = api.get_global_api()
    result = api_.get_edr_assessments_by_alert_ids(edr_alert_ids)

    pprint(result)


if __name__ == '__main__':
    get_edr_alert_id_assessments(sys.argv[1:])
