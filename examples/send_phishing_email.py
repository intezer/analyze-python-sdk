import io
import sys
from pprint import pprint

from intezer_sdk import api
from intezer_sdk.alerts import Alert

def send_phishing_email(path_to_eml_file):
    api.set_global_api('<api_key>')

    with open(path_to_eml_file, 'rb') as file:
        binary_data = io.BytesIO(file.read())

    alert = Alert.send_phishing_email(raw_email=binary_data)
    pprint(alert.alert_id)


if __name__ == '__main__':
    send_phishing_email(*sys.argv[1:])
