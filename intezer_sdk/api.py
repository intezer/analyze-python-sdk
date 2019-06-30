import os
import typing
from typing import Optional

import requests
from requests import Response

from intezer_sdk import consts
from intezer_sdk import errors

try:
    from http import HTTPStatus
except ImportError:
    import httplib as HTTPStatus

_global_api = None


class IntezerApi(object):
    def __init__(self,
                 api_version=None,
                 api_key=None,
                 base_url=None):  # type: (str, str,str) -> None
        self.full_url = base_url + api_version
        self.api_key = api_key
        self._access_token = None
        self._session = None

    def _request(self,
                 method,
                 path,
                 data=None,
                 headers=None,
                 files=None):  # type: (str, str, dict, dict, dict) -> Response
        if not self._session:
            self.set_session()

        if files:
            response = self._session.request(
                method,
                self.full_url + path,
                files=files,
                data=data or {},
                headers=headers or {}
            )
        else:
            response = self._session.request(
                method,
                self.full_url + path,
                json=data or {},
                headers=headers
            )

        return response

    def analyze_by_hash(self,
                        file_hash,
                        dynamic_unpacking=None,
                        static_unpacking=None):  # type: (str,bool,bool) -> str
        data = self._param_initialize(dynamic_unpacking, static_unpacking)

        data['hash'] = file_hash
        response = self._request(path='/analyze-by-hash', data=data, method='POST')
        self._assert_analysis_reponse_status_code(response)

        return self._get_analysis_id_from_response(response)

    def _analyze_file_stream(self, file_stream: typing.BinaryIO, file_name: str, options: dict) -> str:
        file = {'file': (file_name, file_stream)}

        response = self._request(path='/analyze', files=file, data=options, method='POST')

        self._assert_analysis_reponse_status_code(response)

        return self._get_analysis_id_from_response(response)

    def analyze_by_file(self,
                        file_path: str = None,
                        file_stream: typing.BinaryIO = None,
                        dynamic_unpacking: bool = None,
                        static_unpacking: bool = None) -> str:
        options = self._param_initialize(dynamic_unpacking, static_unpacking)

        if file_stream:
            return self._analyze_file_stream(file_stream, 'file', options)

        with open(file_path, 'rb') as file_to_upload:
            return self._analyze_file_stream(file_to_upload, os.path.basename(file_path), options)

    def get_latest_analysis(self, file_hash: str) -> Optional[dict]:
        response = self._request(path=f'/files/{file_hash}', method='GET')

        if response.status_code == HTTPStatus.NOT_FOUND:
            return None

        response.raise_for_status()

        return response.json()['result']

    def get_analysis_response(self, analyses_id):  # type: (str) -> Response
        response = self._request(path='/analyses/{}'.format(analyses_id), method='GET')
        response.raise_for_status()

        return response

    def index_by_sha256(self, sha256, index_as, family_name=None):  # type: (str, IndexType, str) -> Response
        data = {'index_as': index_as.value}
        if family_name:
            data['family_name'] = family_name

        response = self._request(path='/files/{}/index'.format(sha256), data=data, method='POST')
        self._assert_index_reponse_status_code(response)

        return self._get_index_id_from_response(response)

    def index_by_file(self, file_path, index_as, family_name=None):  # type: (str, IndexType, str) -> Response
        data = {'index_as': index_as.value}
        if family_name:
            data['family_name'] = family_name

        with open(file_path, 'rb') as file_to_upload:
            file = {'file': (os.path.basename(file_path), file_to_upload)}

            response = self._request(path='/files/index', data=data, files=file, method='POST')

        self._assert_index_reponse_status_code(response)

        return self._get_index_id_from_response(response)

    def get_index_response(self, index_id):  # type: (str) -> Response
        response = self._request(path='/files/index/{}'.format(index_id), method='GET')
        response.raise_for_status()

        return response

    def _set_access_token(self, api_key):  # type: (str) -> None
        if self._access_token is None:
            response = requests.post(self.full_url + '/get-access-token', json={'api_key': api_key})

            if response.status_code in (HTTPStatus.UNAUTHORIZED, HTTPStatus.BAD_REQUEST):
                raise errors.InvalidApiKey()
            elif response.status_code != HTTPStatus.OK:
                response.raise_for_status()

            self._access_token = response.json()['result']

    def set_session(self):
        self._session = requests.session()
        self._set_access_token(self.api_key)
        self._session.headers['Authorization'] = 'Bearer {}'.format(self._access_token)
        self._session.headers['User-Agent'] = consts.USER_AGENT

    def _param_initialize(self, dynamic_unpacking=None, static_unpacking=None):
        data = {}

        if dynamic_unpacking is not None:
            data['disable_dynamic_execution'] = not dynamic_unpacking
        if static_unpacking is not None:
            data['disable_static_extraction'] = not static_unpacking

        return data

    def _assert_analysis_reponse_status_code(self, response):
        if response.status_code == HTTPStatus.NOT_FOUND:
            raise errors.HashDoesNotExistError()
        elif response.status_code == HTTPStatus.CONFLICT:
            raise errors.AnalysisIsAlreadyRunning()
        elif response.status_code == HTTPStatus.FORBIDDEN:
            raise errors.InsufficientQuota()
        elif response.status_code != HTTPStatus.CREATED:
            raise errors.IntezerError('Error in response status code:{}'.format(response.status_code))

    def _assert_index_reponse_status_code(self, response):
        if response.status_code == HTTPStatus.NOT_FOUND:
            raise errors.HashDoesNotExistError()
        elif response.status_code != HTTPStatus.CREATED:
            raise errors.IntezerError('Error in response status code:{}'.format(response.status_code))

    def _get_analysis_id_from_response(self, response):
        return response.json()['result_url'].split('/')[2]

    def _get_index_id_from_response(self, response):
        return response.json()['result_url'].split('/')[3]


def get_global_api():  # type: () -> IntezerApi
    global _global_api

    if not _global_api:
        raise errors.GlobalApiIsNotInitialized()

    return _global_api


def set_global_api(api_key=None, api_version=None, base_url=None):
    global _global_api
    api_key = os.environ.get('INTEZER_ANALYZE_API_KEY') or api_key
    _global_api = IntezerApi(api_version or consts.API_VERSION, api_key, base_url or consts.BASE_URL)
