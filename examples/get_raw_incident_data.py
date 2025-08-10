import sys
from pprint import pprint

from intezer_sdk import api
from intezer_sdk.incidents import Incident


def get_raw_incident_data(incident_id: str, environment: str):
    api.set_global_api('<api_key>')

    incident = Incident(incident_id=incident_id)
    raw_data = incident.get_raw_data(environment=environment)
    pprint(f'Incident convenience method: {raw_data}')


if __name__ == '__main__':
    get_raw_incident_data(*sys.argv[1:])
