import requests

from intezer_sdk import SDK_VERSION
from intezer_sdk.api_config import api_config


class IntezerApi(object):
    USER_AGENT = 'intzersdk-python-%s' % SDK_VERSION

    def __init__(self, api_version=None, api_key=None):
        self.full_url = api_config['BASE_URL'] + (api_version or api_config['API_VERSION'])
        self.api_key = api_key or api_config['API_KEY']
        self._access_token = None

    def request(self,
                method,
                path,
                params=None,
                headers=None,
                files=None):
        if not params:
            params = {}
        if not headers:
            headers = {}

        headers['User-Agent'] = self.USER_AGENT

        session = requests.session()
        session.headers['Authorization'] = 'Bearer %s' % self.get_access_token(self.api_key)

        if method in ('GET', 'DELETE'):
            response = session.request(
                method,
                self.full_url + path,
                params=params,
                headers=headers,
                files=files
            )

        else:
            response = session.request(
                method,
                self.full_url + path,
                json=params,
                headers=headers,
                files=files
            )

        return response

    def get_access_token(self, api_key):
        if self._access_token is None:
            response = requests.post(self.full_url + '/get-access-token', json={'api_key': api_key})
            self._access_token = response.json()['result']

        return self._access_token
