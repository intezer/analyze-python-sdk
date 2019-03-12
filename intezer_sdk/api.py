import os

import requests

from intezer_sdk.consts import API_VERSION
from intezer_sdk.consts import BASE_URL
from intezer_sdk.consts import USER_AGENT
from intezer_sdk.errors import AnalysisIsAlreadyRunning
from intezer_sdk.errors import GlobalApiIsNotInitialized
from intezer_sdk.errors import HashDoesNotExistError
from intezer_sdk.errors import InsufficientQuota
from intezer_sdk.errors import IntezerError

try:
    from http import HTTPStatus
except ImportError:
    import httplib as HTTPStatus


class IntezerApi(object):
    def __init__(self,
                 api_version=None,
                 api_key=None,
                 base_url=None):  # type: (str, str,str) -> None
        self.full_url = base_url + api_version
        self.api_key = api_key or os.environ.get('INTEZER_ANALYZE_API_KEY')
        self._access_token = None
        self.session = requests.session()
        self.session.headers['Authorization'] = 'Bearer {}'.format(self.set_access_token(self.api_key))
        self.session.headers['User-Agent'] = USER_AGENT

    def request(self,
                method,
                path,
                params=None,
                headers=None,
                files=None):  # type: (str, str, dict, dict, dict) -> Response
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

    def set_access_token(self, api_key):  # type: (str) -> str
        if self._access_token is None:
            response = requests.post(self.full_url + '/get-access-token', json={'api_key': api_key})
            self._access_token = response.json()['result']

        return self._access_token

    def analyze_by_hash(self,
                        file_hash,
                        dynamic_unpacking=None,
                        static_unpacking=None):  # type: (str,bool,bool) -> str
        params = self._param_initialize(dynamic_unpacking, static_unpacking)

        params['hash'] = file_hash
        response = self.request(path='/analyze-by-hash', params=params, method='POST')
        self._handle_reponse_status_code(response)

        return response.json()['result_url'].split('/')[2]

    def analyze_by_file(self,
                        file_path,
                        dynamic_unpacking=None,
                        static_unpacking=None):  # type: (str,bool,bool) -> str
        params = self._param_initialize(dynamic_unpacking, static_unpacking)

        with open(file_path, 'rb') as file_to_upload:
            file = {'file': ('file_name', file_to_upload)}

        response = self.request(path='/analyze', files=file, params=params, method='POST')

        assert response.status_code == HTTPStatus.CREATED

        return response.json()['result_url'].split('/')[2]

    def get_analysis_response(self, analyses_id):  # type: (str) -> Response
        response = self.request(path='/analyses/{}'.format(analyses_id), method='GET')
        response.raise_for_status()

        return response

    def _param_initialize(self, dynamic_unpacking=None, static_unpacking=None):
        params = {}

        if dynamic_unpacking is not None:
            params['dynamic_unpacking'] = dynamic_unpacking
        if static_unpacking is not None:
            params['static_unpacking'] = static_unpacking

        return params

    def _handle_reponse_status_code(self, response):
        if response.status_code == HTTPStatus.NOT_FOUND:
            raise HashDoesNotExistError()
        elif response.status_code == HTTPStatus.CONFLICT:
            raise AnalysisIsAlreadyRunning()
        elif response.status_code == HTTPStatus.FORBIDDEN:
            raise InsufficientQuota()
        elif response.status_code != HTTPStatus.CREATED:
            raise IntezerError('Error in response status code:{}'.format(response.status_code))


global_api = None


def get_global_api():
    global global_api

    if not global_api:
        raise GlobalApiIsNotInitialized()

    return global_api


def set_global_api(api_key):
    global global_api
    global_api = IntezerApi(API_VERSION, api_key, BASE_URL)
