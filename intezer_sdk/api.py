import os
import typing
from http import HTTPStatus

import requests
import requests.adapters
from requests import Response

from intezer_sdk import consts
from intezer_sdk import errors
from intezer_sdk.consts import IndexType

_global_api = None


def raise_for_status(response: requests.Response,
                     statuses_to_ignore: typing.List[typing.Union[HTTPStatus, int]] = None,
                     allowed_statuses: typing.List[typing.Union[HTTPStatus, int]] = None):
    """Raises stored :class:`HTTPError`, if one occurred."""

    http_error_msg = ''
    if isinstance(response.reason, bytes):
        reason = response.reason.decode('utf-8', 'ignore')
    else:
        reason = response.reason

    if statuses_to_ignore and response.status_code in statuses_to_ignore:
        return
    elif allowed_statuses and response.status_code not in allowed_statuses:
        http_error_msg = '%s Custom Error: %s for url: %s' % (response.status_code, reason, response.url)
    elif 400 <= response.status_code < 500:
        if response.status_code != 400:
            http_error_msg = '%s Client Error: %s for url: %s' % (response.status_code, reason, response.url)
        else:
            # noinspection PyBroadException
            try:
                error = response.json()
                http_error_msg = '\n'.join(['{}:{}.'.format(key, value) for key, value in error['message'].items()])
            except Exception:
                http_error_msg = '%s Client Error: %s for url: %s' % (response.status_code, reason, response.url)
    elif 500 <= response.status_code < 600:
        http_error_msg = '%s Server Error: %s for url: %s' % (response.status_code, reason, response.url)

    if http_error_msg:
        # noinspection PyBroadException
        try:
            data = response.json()
            http_error_msg = '%s, server returns %s, details: %s' % (http_error_msg, data['error'], data.get('details'))
        except Exception:
            pass

        raise requests.HTTPError(http_error_msg, response=response)


class IntezerApi:
    def __init__(self, api_version: str = None, api_key: str = None, base_url: str = None, verify_ssl: bool = True):
        self.full_url = base_url + api_version
        self.api_key = api_key
        self._access_token = None
        self._session = None
        self._verify_ssl = verify_ssl

    def _request(self,
                 method: str,
                 path: str,
                 data: dict = None,
                 headers: dict = None,
                 files: dict = None) -> Response:
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

    def _request_with_refresh_expired_access_token(self,
                                                   method: str,
                                                   path: str,
                                                   data: dict = None,
                                                   headers: dict = None,
                                                   files: dict = None) -> Response:
        response = self._request(method, path, data, headers, files)

        if response.status_code == HTTPStatus.UNAUTHORIZED:
            self._access_token = None
            self.set_session()
            response = self._request(method, path, data, headers, files)

        return response

    def analyze_by_hash(self,
                        file_hash: str,
                        disable_dynamic_unpacking: bool = None,
                        disable_static_unpacking: bool = None) -> str:
        data = self._param_initialize(disable_dynamic_unpacking, disable_static_unpacking)

        data['hash'] = file_hash
        response = self._request_with_refresh_expired_access_token(path='/analyze-by-hash', data=data, method='POST')
        self._assert_analysis_response_status_code(response)

        return self._get_analysis_id_from_response(response)

    def _analyze_file_stream(self, file_stream: typing.BinaryIO, file_name: str, options: dict) -> str:
        file = {'file': (file_name, file_stream)}

        response = self._request_with_refresh_expired_access_token(path='/analyze',
                                                                   files=file,
                                                                   data=options,
                                                                   method='POST')

        self._assert_analysis_response_status_code(response)

        return self._get_analysis_id_from_response(response)

    def analyze_by_file(self,
                        file_path: str = None,
                        file_stream: typing.BinaryIO = None,
                        disable_dynamic_unpacking: bool = None,
                        disable_static_unpacking: bool = None,
                        file_name: str = None,
                        code_item_type: str = None) -> typing.Optional[str]:
        options = self._param_initialize(disable_dynamic_unpacking, disable_static_unpacking, code_item_type)

        if file_stream:
            return self._analyze_file_stream(file_stream, file_name, options)

        with open(file_path, 'rb') as file_to_upload:
            return self._analyze_file_stream(file_to_upload, file_name or os.path.basename(file_path), options)

    def get_latest_analysis(self, file_hash: str) -> typing.Optional[dict]:
        response = self._request_with_refresh_expired_access_token(path='/files/{}'.format(file_hash), method='GET')

        if response.status_code == HTTPStatus.NOT_FOUND:
            return None

        raise_for_status(response)

        return response.json()['result']

    def get_analysis_response(self, analyses_id: str) -> Response:
        response = self._request_with_refresh_expired_access_token(path='/analyses/{}'.format(analyses_id),
                                                                   method='GET')
        raise_for_status(response)

        return response

    def get_family_info(self, family_id: str) -> typing.Optional[dict]:
        response = self._request_with_refresh_expired_access_token('GET', '/families/{}/info'.format(family_id))
        if response.status_code == HTTPStatus.NOT_FOUND:
            return None

        raise_for_status(response, allowed_statuses=[HTTPStatus.OK])
        return response.json()['result']

    def get_family_by_name(self, family_name: str) -> typing.Optional[typing.Dict[str, typing.Any]]:
        response = self._request_with_refresh_expired_access_token('GET', '/families', {'family_name': family_name})
        if response.status_code == HTTPStatus.NOT_FOUND:
            return None

        raise_for_status(response, allowed_statuses=[HTTPStatus.OK])
        return response.json()['result']

    def get_sub_analyses_by_id(self, analysis_id: str) -> typing.Optional[list]:
        response = self._request_with_refresh_expired_access_token(path='/analyses/{}/sub-analyses'.format(analysis_id),
                                                                   method='GET')
        raise_for_status(response)

        return response.json()['sub_analyses']

    def get_sub_analysis_code_reuse_by_id(self,
                                          composed_analysis_id: str,
                                          sub_analysis_id: str) -> typing.Optional[dict]:
        response = self._request_with_refresh_expired_access_token(path='/analyses/{}/sub-analyses/{}/code-reuse'
                                                                   .format(composed_analysis_id, sub_analysis_id),
                                                                   method='GET')
        if response.status_code == HTTPStatus.CONFLICT:
            return None

        raise_for_status(response)

        return response.json()

    def get_sub_analysis_metadata_by_id(self, composed_analysis_id: str, sub_analysis_id: str) -> dict:
        response = self._request_with_refresh_expired_access_token(path='/analyses/{}/sub-analyses/{}/metadata'
                                                                   .format(composed_analysis_id, sub_analysis_id),
                                                                   method='GET')
        raise_for_status(response)

        return response.json()

    def get_sub_analysis_related_files_by_family_id(self,
                                                    composed_analysis_id: str,
                                                    sub_analysis_id: str,
                                                    family_id: str) -> str:
        response = self._request_with_refresh_expired_access_token(
            path='/analyses/{}/sub-analyses/{}/code-reuse/families/{}/find-related-files'.format(
                composed_analysis_id, sub_analysis_id, family_id),
            method='POST')

        raise_for_status(response)

        return response.json()['result_url']

    def get_sub_analysis_account_related_samples_by_id(self, composed_analysis_id: str, sub_analysis_id: str) -> str:
        response = self._request_with_refresh_expired_access_token(
            path='/analyses/{}/sub-analyses/{}/get-account-related-samples'.format(composed_analysis_id,
                                                                                   sub_analysis_id),
            method='POST')

        raise_for_status(response)

        return response.json()['result_url']

    def generate_sub_analysis_vaccine_by_id(self, composed_analysis_id: str, sub_analysis_id: str) -> str:
        response = self._request_with_refresh_expired_access_token(
            path='/analyses/{}/sub-analyses/{}/generate-vaccine'.format(composed_analysis_id, sub_analysis_id),
            method='POST')

        raise_for_status(response)

        return response.json()['result_url']

    def get_strings_by_id(self, composed_analysis_id: str, sub_analysis_id: str) -> str:
        response = self._request_with_refresh_expired_access_token(
            path='/analyses/{}/sub-analyses/{}/strings'.format(composed_analysis_id, sub_analysis_id),
            method='POST')

        raise_for_status(response)

        return response.json()['result_url']

    def get_string_related_samples_by_id(self,
                                         composed_analysis_id: str,
                                         sub_analysis_id: str,
                                         string_value: str) -> str:
        response = self._request_with_refresh_expired_access_token(
            path='/analyses/{}/sub-analyses/{}/string-related-samples'.format(composed_analysis_id, sub_analysis_id),
            method='POST',
            data={'string_value': string_value})

        raise_for_status(response)

        return response.json()['result_url']

    def get_url_result(self, url: str) -> typing.Optional[Response]:
        response = self._request_with_refresh_expired_access_token(path=url, method='GET')

        raise_for_status(response)

        response_json = response.json()

        if 'error' in response_json:
            raise errors.IntezerError('response error: {}'.format(response_json['error']))

        return response

    def download_file_by_sha256(self, sha256: str, path: str) -> None:
        if os.path.isdir(path):
            path = os.path.join(path, sha256 + '.sample')
        if os.path.isfile(path):
            raise FileExistsError()

        response = self._request_with_refresh_expired_access_token(path='/files/{}/download'.format(sha256),
                                                                   method='GET')

        raise_for_status(response)

        with open(path, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)

    def index_by_sha256(self, sha256: str, index_as: IndexType, family_name: str = None) -> Response:
        data = {'index_as': index_as.value}
        if family_name:
            data['family_name'] = family_name

        response = self._request_with_refresh_expired_access_token(path='/files/{}/index'.format(sha256), data=data,
                                                                   method='POST')
        self._assert_index_response_status_code(response)

        return self._get_index_id_from_response(response)

    def index_by_file(self, file_path: str, index_as: IndexType, family_name: str = None) -> Response:
        data = {'index_as': index_as.value}
        if family_name:
            data['family_name'] = family_name

        with open(file_path, 'rb') as file_to_upload:
            file = {'file': (os.path.basename(file_path), file_to_upload)}

            response = self._request_with_refresh_expired_access_token(path='/files/index',
                                                                       data=data,
                                                                       files=file,
                                                                       method='POST')

        self._assert_index_response_status_code(response)

        return self._get_index_id_from_response(response)

    def get_index_response(self, index_id: str) -> Response:
        response = self._request_with_refresh_expired_access_token(path='/files/index/{}'.format(index_id),
                                                                   method='GET')
        raise_for_status(response)

        return response

    def _set_access_token(self, api_key: str):
        response = requests.post(self.full_url + '/get-access-token', json={'api_key': api_key})

        if response.status_code in (HTTPStatus.UNAUTHORIZED, HTTPStatus.BAD_REQUEST):
            raise errors.InvalidApiKey(response)
        if response.status_code != HTTPStatus.OK:
            raise_for_status(response)

        self._access_token = response.json()['result']

    def set_session(self):
        self._session = requests.session()
        self._session.mount('https://', requests.adapters.HTTPAdapter(max_retries=3))
        self._session.verify = self._verify_ssl
        self._set_access_token(self.api_key)
        self._session.headers['Authorization'] = 'Bearer {}'.format(self._access_token)
        self._session.headers['User-Agent'] = consts.USER_AGENT

    @staticmethod
    def _param_initialize(disable_dynamic_unpacking: bool = None,
                          disable_static_unpacking: bool = None,
                          code_item_type: str = None):
        data = {}

        if disable_dynamic_unpacking is not None:
            data['disable_dynamic_execution'] = disable_dynamic_unpacking
        if disable_static_unpacking is not None:
            data['disable_static_extraction'] = disable_static_unpacking
        if code_item_type:
            data['code_item_type'] = code_item_type

        return data

    @staticmethod
    def _assert_analysis_response_status_code(response: Response):
        if response.status_code == HTTPStatus.NOT_FOUND:
            raise errors.HashDoesNotExistError(response)
        elif response.status_code == HTTPStatus.CONFLICT:
            raise errors.AnalysisIsAlreadyRunning(response)
        elif response.status_code == HTTPStatus.FORBIDDEN:
            raise errors.InsufficientQuota(response)
        elif response.status_code != HTTPStatus.CREATED:
            raise errors.ServerError('Error in response status code:{}'.format(response.status_code), response)

    @staticmethod
    def _assert_index_response_status_code(response: Response):
        if response.status_code == HTTPStatus.NOT_FOUND:
            raise errors.HashDoesNotExistError(response)
        elif response.status_code != HTTPStatus.CREATED:
            raise errors.ServerError('Error in response status code:{}'.format(response.status_code), response)

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


def set_global_api(api_key: str = None, api_version: str = None, base_url: str = None, verify_ssl: bool = True):
    global _global_api
    api_key = api_key or os.environ.get('INTEZER_ANALYZE_API_KEY')
    _global_api = IntezerApi(api_version or consts.API_VERSION, api_key, base_url or consts.BASE_URL, verify_ssl)
