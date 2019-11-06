import os
import typing
from http import HTTPStatus
from typing import Optional

import requests
from requests import Response

from intezer_sdk import consts
from intezer_sdk import errors
from intezer_sdk.consts import IndexType

_global_api = None


class IntezerApi(object):
    def __init__(self, api_version: str = None, api_key: str = None, base_url: str = None):
        self.full_url = base_url + api_version
        self.api_key = api_key
        self._access_token = None
        self._session = None

    def _request(self, method: str, path: str, data: dict = None, headers: dict = None, files: dict = None) -> Response:
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
                        file_hash: str,
                        disable_dynamic_unpacking: bool = None,
                        disable_static_unpacking: bool = None) -> str:
        data = self._param_initialize(disable_dynamic_unpacking, disable_static_unpacking)

        data['hash'] = file_hash
        response = self._request(path='/analyze-by-hash', data=data, method='POST')
        self._assert_analysis_response_status_code(response)

        return self._get_analysis_id_from_response(response)

    def _analyze_file_stream(self, file_stream: typing.BinaryIO, file_name: str, options: dict) -> str:
        file = {'file': (file_name, file_stream)}

        response = self._request(path='/analyze', files=file, data=options, method='POST')

        self._assert_analysis_response_status_code(response)

        return self._get_analysis_id_from_response(response)

    def analyze_by_file(self,
                        file_path: str = None,
                        file_stream: typing.BinaryIO = None,
                        disable_dynamic_unpacking: bool = None,
                        disable_static_unpacking: bool = None,
                        file_name: str = None,
                        code_item_type: str = None) -> str:
        options = self._param_initialize(disable_dynamic_unpacking, disable_static_unpacking, code_item_type)

        if file_stream:
            return self._analyze_file_stream(file_stream, file_name, options)

        with open(file_path, 'rb') as file_to_upload:
            return self._analyze_file_stream(file_to_upload, file_name or os.path.basename(file_path), options)

    def get_latest_analysis(self, file_hash: str) -> Optional[dict]:
        response = self._request(path='/files/{}'.format(file_hash), method='GET')

        if response.status_code == HTTPStatus.NOT_FOUND:
            return None

        response.raise_for_status()

        return response.json()['result']

    def get_analysis_response(self, analyses_id) -> Response:
        response = self._request(path='/analyses/{}'.format(analyses_id), method='GET')
        response.raise_for_status()

        return response

    def index_by_sha256(self, sha256: str, index_as: IndexType, family_name: str = None) -> Response:
        data = {'index_as': index_as.value}
        if family_name:
            data['family_name'] = family_name

        response = self._request(path='/files/{}/index'.format(sha256), data=data, method='POST')
        self._assert_index_response_status_code(response)

        return self._get_index_id_from_response(response)

    def index_by_file(self, file_path: str, index_as: IndexType, family_name: str = None) -> Response:
        data = {'index_as': index_as.value}
        if family_name:
            data['family_name'] = family_name

        with open(file_path, 'rb') as file_to_upload:
            file = {'file': (os.path.basename(file_path), file_to_upload)}

            response = self._request(path='/files/index', data=data, files=file, method='POST')

        self._assert_index_response_status_code(response)

        return self._get_index_id_from_response(response)

    def get_index_response(self, index_id: str) -> Response:
        response = self._request(path='/files/index/{}'.format(index_id), method='GET')
        response.raise_for_status()

        return response

    def _set_access_token(self, api_key: str):
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

    @staticmethod
    def _param_initialize(disable_dynamic_unpacking: bool = None,
                          disable_static_unpacking: bool = None,
                          code_item_type: str = None):
        data = {}

        if disable_dynamic_unpacking:
            data['disable_dynamic_execution'] = disable_dynamic_unpacking
        if disable_static_unpacking:
            data['disable_static_extraction'] = disable_static_unpacking
        if code_item_type:
            data['code_item_type'] = code_item_type

        return data

    @staticmethod
    def _assert_analysis_response_status_code(response: Response):
        if response.status_code == HTTPStatus.NOT_FOUND:
            raise errors.HashDoesNotExistError()
        elif response.status_code == HTTPStatus.CONFLICT:
            raise errors.AnalysisIsAlreadyRunning()
        elif response.status_code == HTTPStatus.FORBIDDEN:
            raise errors.InsufficientQuota()
        elif response.status_code != HTTPStatus.CREATED:
            raise errors.IntezerError('Error in response status code:{}'.format(response.status_code))

    @staticmethod
    def _assert_index_response_status_code(response: Response):
        if response.status_code == HTTPStatus.NOT_FOUND:
            raise errors.HashDoesNotExistError()
        elif response.status_code != HTTPStatus.CREATED:
            raise errors.IntezerError('Error in response status code:{}'.format(response.status_code))

    @staticmethod
    def _get_analysis_id_from_response(response: Response):
        return response.json()['result_url'].split('/')[2]

    @staticmethod
    def _get_index_id_from_response(response: Response):
        return response.json()['result_url'].split('/')[3]


def get_global_api() -> IntezerApi:
    global _global_api

    if not _global_api:
        raise errors.GlobalApiIsNotInitialized()

    return _global_api


def set_global_api(api_key: str = None, api_version: str = None, base_url: str = None):
    global _global_api
    api_key = api_key or os.environ.get('INTEZER_ANALYZE_API_KEY')
    _global_api = IntezerApi(api_version or consts.API_VERSION, api_key, base_url or consts.BASE_URL)
