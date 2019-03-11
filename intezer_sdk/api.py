try:
    from http import HTTPStatus
except ImportError:
    import httplib as HTTPStatus
import requests

from intezer_sdk.consts import USER_AGENT
from intezer_sdk.exceptions import AnalysisAlreadyRunning
from intezer_sdk.exceptions import HashDoesNotExistError
from intezer_sdk.exceptions import IntezerError

BASE_URL = 'https://analyze.intezer.com/api/'
API_VERSION = 'v2-0'
API_KEY = '<api_key>'


class IntezerApi(object):
    def __init__(self,
                 api_version=None,  # type: str
                 api_key=None  # type: str
                 ):
        self.full_url = BASE_URL + (api_version or API_VERSION)
        self.api_key = api_key or API_KEY
        self._access_token = None
        self.session = requests.session()
        self.session.headers['Authorization'] = 'Bearer {0}'.format(self.get_access_token(self.api_key))
        self.session.headers['User-Agent'] = USER_AGENT

    def request(self,
                method,  # type: str
                path,  # type: str
                params=None,  # type: dict
                headers=None,  # type: dict
                files=None  # type: dict
                ):

        if method in ('GET', 'DELETE'):
            response = self.session.request(
                method,
                self.full_url + path,
                params=params or {},
                headers=headers,
                files=files
            )

        else:
            response = self.session.request(
                method,
                self.full_url + path,
                json=params or {},
                headers=headers or {},
                files=files
            )

        return response

    def get_access_token(self, api_key):
        if self._access_token is None:
            response = requests.post(self.full_url + '/get-access-token', json={'api_key': api_key})
            self._access_token = response.json()['result']

        return self._access_token

    def analyze_by_hash(self, file_hash, dynamic_unpacking=None, static_unpacking=None):
        params = {}

        if dynamic_unpacking:
            params['dynamic_unpacking'] = dynamic_unpacking
        if static_unpacking:
            params['static_unpacking'] = static_unpacking

        params['hash'] = file_hash
        response = self.request(path='/analyze-by-hash', params=params, method='POST')
        if response.status_code == HTTPStatus.NOT_FOUND:
            raise HashDoesNotExistError()
        elif response.status_code == HTTPStatus.CONFLICT:
            raise AnalysisAlreadyRunning()
        elif response.status_code is not HTTPStatus.CREATED:
            assert IntezerError()

        return response.json()['result_url'].split('/')[2]

    def analyze_by_files(self, files, dynamic_unpacking=None, static_unpacking=None):
        params = {}

        if dynamic_unpacking:
            params['dynamic_unpacking'] = dynamic_unpacking
        if static_unpacking:
            params['static_unpacking'] = static_unpacking

        response = self.request(path='/analyze', files=files, params=params, method='POST')

        assert response.status_code == HTTPStatus.CREATED

        return response.json()['result_url'].split('/')[2]

    def get_analysis_response(self, analyses_id):
        response = self.request(path='/analyses/{0}'.format(analyses_id), method='GET')
        response.raise_for_status()

        return response
