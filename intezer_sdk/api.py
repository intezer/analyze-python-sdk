import os
from http import HTTPStatus
from typing import Any
from typing import BinaryIO
from typing import Dict
from typing import IO
from typing import List
from typing import Optional
from typing import Union

import requests
import requests.adapters
from requests import Response

from intezer_sdk import consts
from intezer_sdk import errors
from intezer_sdk._util import deprecated
from intezer_sdk.consts import IndexType
from intezer_sdk.consts import OnPremiseVersion

_global_api: Optional['IntezerApi'] = None


def raise_for_status(response: requests.Response,
                     statuses_to_ignore: List[Union[HTTPStatus, int]] = None,
                     allowed_statuses: List[Union[HTTPStatus, int]] = None):
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
    def __init__(self,
                 api_version: str = None,
                 api_key: str = None,
                 base_url: str = None,
                 verify_ssl: bool = True,
                 on_premise_version: OnPremiseVersion = None,
                 user_agent: str = None):
        self.full_url = base_url + api_version
        self.api_key = api_key
        self._access_token = None
        self._session = None
        self._verify_ssl = verify_ssl
        self.on_premise_version = on_premise_version
        if user_agent:
            user_agent = f'{consts.USER_AGENT}/{user_agent}'
        else:
            user_agent = consts.USER_AGENT
        self.user_agent = user_agent

    def _request(self,
                 method: str,
                 path: str,
                 data: dict = None,
                 headers: dict = None,
                 files: dict = None,
                 stream: bool = None) -> Response:
        if not self._session:
            self.set_session()

        if files:
            response = self._session.request(
                method,
                self.full_url + path,
                files=files,
                data=data or {},
                headers=headers or {},
                stream=stream
            )
        else:
            response = self._session.request(
                method,
                self.full_url + path,
                json=data or {},
                headers=headers,
                stream=stream
            )

        return response

    def request_with_refresh_expired_access_token(self,
                                                  method: str,
                                                  path: str,
                                                  data: dict = None,
                                                  headers: dict = None,
                                                  files: dict = None,
                                                  stream: bool = None) -> Response:
        response = self._request(method, path, data, headers, files)

        if response.status_code == HTTPStatus.UNAUTHORIZED:
            self._access_token = None
            self.set_session()
            response = self._request(method, path, data, headers, files, stream)

        return response

    def analyze_by_hash(self,
                        file_hash: str,
                        disable_dynamic_unpacking: Optional[bool],
                        disable_static_unpacking: Optional[bool],
                        sandbox_command_line_arguments: str = None,
                        **additional_parameters) -> str:
        data = self._param_initialize(disable_dynamic_unpacking=disable_dynamic_unpacking,
                                      disable_static_unpacking=disable_static_unpacking,
                                      sandbox_command_line_arguments=sandbox_command_line_arguments,
                                      **additional_parameters)

        data['hash'] = file_hash
        response = self.request_with_refresh_expired_access_token(path='/analyze-by-hash', data=data, method='POST')
        self._assert_analysis_response_status_code(response)

        return self._get_analysis_id_from_response(response)

    def analyze_by_download_url(self,
                                download_url: str,
                                disable_dynamic_unpacking: bool = None,
                                disable_static_unpacking: bool = None,
                                code_item_type: str = None,
                                zip_password: str = None,
                                sandbox_command_line_arguments: str = None,
                                **additional_parameters) -> str:
        data = self._param_initialize(disable_dynamic_unpacking=disable_dynamic_unpacking,
                                      disable_static_unpacking=disable_static_unpacking,
                                      code_item_type=code_item_type,
                                      zip_password=zip_password,
                                      sandbox_command_line_arguments=sandbox_command_line_arguments,
                                      **additional_parameters)

        data['download_url'] = download_url
        response = self.request_with_refresh_expired_access_token(path='/analyze-by-url', data=data, method='POST')
        self._assert_analysis_response_status_code(response)

        return self._get_analysis_id_from_response(response)

    def _analyze_file_stream(self, file_stream: BinaryIO, file_name: str, options: dict) -> str:
        file = {'file': (file_name, file_stream)}

        response = self.request_with_refresh_expired_access_token(path='/analyze',
                                                                  files=file,
                                                                  data=options,
                                                                  method='POST')

        self._assert_analysis_response_status_code(response)

        return self._get_analysis_id_from_response(response)

    def analyze_by_file(self,
                        file_path: str = None,
                        file_stream: BinaryIO = None,
                        disable_dynamic_unpacking: bool = None,
                        disable_static_unpacking: bool = None,
                        file_name: str = None,
                        code_item_type: str = None,
                        zip_password: str = None,
                        sandbox_command_line_arguments: str = None,
                        **additional_parameters) -> Optional[str]:
        options = self._param_initialize(disable_dynamic_unpacking=disable_dynamic_unpacking,
                                         disable_static_unpacking=disable_static_unpacking,
                                         code_item_type=code_item_type,
                                         zip_password=zip_password,
                                         sandbox_command_line_arguments=sandbox_command_line_arguments,
                                         **additional_parameters)

        if file_stream:
            return self._analyze_file_stream(file_stream, file_name, options)

        with open(file_path, 'rb') as file_to_upload:
            return self._analyze_file_stream(file_to_upload, file_name, options)

    def get_latest_analysis(self,
                            file_hash: str,
                            private_only: bool = False,
                            **additional_parameters) -> Optional[dict]:

        if not self.on_premise_version or self.on_premise_version > OnPremiseVersion.V21_11:
            options = {'should_get_only_private_analysis': private_only, **additional_parameters}
        else:
            options = {}

        response = self.request_with_refresh_expired_access_token(path='/files/{}'.format(file_hash),
                                                                  method='GET',
                                                                  data=options)

        if response.status_code == HTTPStatus.NOT_FOUND:
            return None

        raise_for_status(response)

        return response.json()['result']

    def get_file_analysis_response(self, analyses_id: str, ignore_not_found: bool) -> Response:
        response = self.request_with_refresh_expired_access_token(path='/analyses/{}'.format(analyses_id),
                                                                  method='GET')
        self._assert_result_response(ignore_not_found, response)

        return response

    @deprecated('This method is deprecated, use get_file_analysis_response instead to be explict')
    def get_analysis_response(self, analyses_id: str) -> Response:
        return self.get_file_analysis_response(analyses_id, False)

    def get_url_analysis_response(self, analyses_id: str, ignore_not_found: bool) -> Response:
        response = self.request_with_refresh_expired_access_token(path='/url/{}'.format(analyses_id),
                                                                  method='GET')
        self._assert_result_response(ignore_not_found, response)

        return response

    def get_endpoint_analysis_response(self, analyses_id: str, ignore_not_found: bool) -> Response:
        response = self.request_with_refresh_expired_access_token(path=f'/endpoint-analyses/{analyses_id}',
                                                                  method='GET')
        self._assert_result_response(ignore_not_found, response)

        return response

    def get_endpoint_sub_analyses(self, analyses_id: str, verdicts: Optional[List[str]]) -> List[dict]:
        data = dict(verdicts=verdicts) if verdicts is not None else None
        response = self.request_with_refresh_expired_access_token(path=f'/endpoint-analyses/{analyses_id}/sub-analyses',
                                                                  method='GET',
                                                                  data=data)
        self._assert_result_response(False, response)

        return response.json()['sub_analyses']

    def get_iocs(self, analyses_id: str) -> Optional[dict]:
        response = self.request_with_refresh_expired_access_token(path='/analyses/{}/iocs'.format(analyses_id),
                                                                  method='GET')
        raise_for_status(response)

        return response.json()['result']

    def get_detection_result_url(self, analyses_id: str) -> Optional[str]:
        response = self.request_with_refresh_expired_access_token(path=f'/analyses/{analyses_id}/detect',
                                                                  method='GET')
        if response.status_code == HTTPStatus.CONFLICT:
            return None
        raise_for_status(response)

        return response.json()['result_url']

    def get_dynamic_ttps(self, analyses_id: str) -> Optional[dict]:
        self.assert_on_premise_above_v21_11()
        response = self.request_with_refresh_expired_access_token(path='/analyses/{}/dynamic-ttps'.format(analyses_id),
                                                                  method='GET')
        raise_for_status(response)

        return response.json()['result']

    def get_family_info(self, family_id: str) -> Optional[dict]:
        response = self.request_with_refresh_expired_access_token('GET', '/families/{}/info'.format(family_id))
        if response.status_code == HTTPStatus.NOT_FOUND:
            return None

        raise_for_status(response, allowed_statuses=[HTTPStatus.OK])
        return response.json()['result']

    def get_family_by_name(self, family_name: str) -> Optional[Dict[str, Any]]:
        response = self.request_with_refresh_expired_access_token('GET', '/families', {'family_name': family_name})
        if response.status_code == HTTPStatus.NOT_FOUND:
            return None

        raise_for_status(response, allowed_statuses=[HTTPStatus.OK])
        return response.json()['result']

    def get_sub_analyses_by_id(self, analysis_id: str) -> Optional[List[dict]]:
        response = self.request_with_refresh_expired_access_token(path='/analyses/{}/sub-analyses'.format(analysis_id),
                                                                  method='GET')
        raise_for_status(response)

        return response.json()['sub_analyses']

    def get_sub_analysis_code_reuse_by_id(self,
                                          composed_analysis_id: str,
                                          sub_analysis_id: str) -> Optional[dict]:
        response = self.request_with_refresh_expired_access_token(path='/analyses/{}/sub-analyses/{}/code-reuse'
                                                                  .format(composed_analysis_id, sub_analysis_id),
                                                                  method='GET')
        if response.status_code == HTTPStatus.CONFLICT:
            return None

        raise_for_status(response)

        return response.json()

    def get_sub_analysis_metadata_by_id(self, composed_analysis_id: str, sub_analysis_id: str) -> dict:
        response = self.request_with_refresh_expired_access_token(path='/analyses/{}/sub-analyses/{}/metadata'
                                                                  .format(composed_analysis_id, sub_analysis_id),
                                                                  method='GET')
        raise_for_status(response)

        return response.json()

    def get_sub_analysis_related_files_by_family_id(self,
                                                    composed_analysis_id: str,
                                                    sub_analysis_id: str,
                                                    family_id: str) -> str:
        response = self.request_with_refresh_expired_access_token(
            path='/analyses/{}/sub-analyses/{}/code-reuse/families/{}/find-related-files'.format(
                composed_analysis_id, sub_analysis_id, family_id),
            method='POST')

        raise_for_status(response)

        return response.json()['result_url']

    def get_sub_analysis_account_related_samples_by_id(self, composed_analysis_id: str, sub_analysis_id: str) -> str:
        response = self.request_with_refresh_expired_access_token(
            path='/analyses/{}/sub-analyses/{}/get-account-related-samples'.format(composed_analysis_id,
                                                                                   sub_analysis_id),
            method='POST')

        raise_for_status(response)

        return response.json()['result_url']

    def get_sub_analysis_capabilities_by_id(self, composed_analysis_id: str, sub_analysis_id: str) -> str:
        self.assert_on_premise_above_v21_11()
        response = self.request_with_refresh_expired_access_token(
            path='/analyses/{}/sub-analyses/{}/capabilities'.format(composed_analysis_id, sub_analysis_id),
            method='POST')

        raise_for_status(response)

        return response.json()['result_url']

    def generate_sub_analysis_vaccine_by_id(self, composed_analysis_id: str, sub_analysis_id: str) -> str:
        response = self.request_with_refresh_expired_access_token(
            path='/analyses/{}/sub-analyses/{}/generate-vaccine'.format(composed_analysis_id, sub_analysis_id),
            method='POST')

        raise_for_status(response)

        return response.json()['result_url']

    def get_strings_by_id(self, composed_analysis_id: str, sub_analysis_id: str) -> dict:
        response = self.request_with_refresh_expired_access_token(
            path='/analyses/{}/sub-analyses/{}/strings'.format(composed_analysis_id, sub_analysis_id),
            method='POST')

        raise_for_status(response)

        return response.json()

    def get_string_related_samples_by_id(self,
                                         composed_analysis_id: str,
                                         sub_analysis_id: str,
                                         string_value: str) -> str:
        response = self.request_with_refresh_expired_access_token(
            path='/analyses/{}/sub-analyses/{}/string-related-samples'.format(composed_analysis_id, sub_analysis_id),
            method='POST',
            data={'string_value': string_value})

        raise_for_status(response)

        return response.json()['result_url']

    def get_url_result(self, url: str) -> Optional[Response]:
        response = self.request_with_refresh_expired_access_token(path=url, method='GET')

        raise_for_status(response)

        response_json = response.json()

        if 'error' in response_json:
            raise errors.IntezerError('response error: {}'.format(response_json['error']))

        return response

    def download_file_by_sha256(self, sha256: str, path: str = None, output_stream: IO = None) -> None:
        if not path and not output_stream:
            raise ValueError('You must provide either path or output_stream')
        elif path and output_stream:
            raise ValueError('You must provide either path or output_stream, not both')

        should_extract_name_from_request = False
        if path:
            if os.path.isdir(path):
                should_extract_name_from_request = True
            elif os.path.isfile(path):
                raise FileExistsError()

        response = self.request_with_refresh_expired_access_token(path='/files/{}/download'.format(sha256),
                                                                  method='GET',
                                                                  stream=bool(path))

        raise_for_status(response)
        if output_stream:
            output_stream.write(response.content)
        else:
            if should_extract_name_from_request:
                try:
                    filename = response.headers['content-disposition'].split('filename=')[1]
                except Exception:
                    filename = f'{sha256}.sample'

                path = os.path.join(path, filename)

            with open(path, 'wb') as file:
                for chunk in response.iter_content(chunk_size=8192):
                    file.write(chunk)

    def index_by_sha256(self, sha256: str, index_as: IndexType, family_name: str = None) -> Response:
        data = {'index_as': index_as.value}
        if family_name:
            data['family_name'] = family_name

        response = self.request_with_refresh_expired_access_token(path='/files/{}/index'.format(sha256), data=data,
                                                                  method='POST')
        self._assert_index_response_status_code(response)

        return self._get_index_id_from_response(response)

    def index_by_file(self, file_path: str, index_as: IndexType, family_name: str = None) -> Response:
        data = {'index_as': index_as.value}
        if family_name:
            data['family_name'] = family_name

        with open(file_path, 'rb') as file_to_upload:
            file = {'file': (os.path.basename(file_path), file_to_upload)}

            response = self.request_with_refresh_expired_access_token(path='/files/index',
                                                                      data=data,
                                                                      files=file,
                                                                      method='POST')

        self._assert_index_response_status_code(response)

        return self._get_index_id_from_response(response)

    def get_index_response(self, index_id: str) -> Response:
        response = self.request_with_refresh_expired_access_token(path='/files/index/{}'.format(index_id),
                                                                  method='GET')
        raise_for_status(response)

        return response

    def _set_access_token(self, api_key: str):
        response = requests.post(self.full_url + '/get-access-token',
                                 json={'api_key': api_key},
                                 verify=self._verify_ssl)

        if response.status_code in (HTTPStatus.UNAUTHORIZED, HTTPStatus.BAD_REQUEST):
            raise errors.InvalidApiKeyError(response)
        if response.status_code != HTTPStatus.OK:
            raise_for_status(response)

        self._access_token = response.json()['result']

    def set_session(self):
        self._session = requests.session()
        self._session.mount('https://', requests.adapters.HTTPAdapter(max_retries=3))
        self._session.verify = self._verify_ssl
        self._set_access_token(self.api_key)
        self._session.headers['Authorization'] = 'Bearer {}'.format(self._access_token)
        self._session.headers['User-Agent'] = self.user_agent

    def analyze_url(self, url: str, **additional_parameters) -> Optional[str]:
        self.assert_any_on_premise()
        response = self.request_with_refresh_expired_access_token(method='POST',
                                                                  path='/url',
                                                                  data=dict(url=url, **additional_parameters))
        self._assert_analysis_response_status_code(response)

        return self._get_analysis_id_from_response(response)

    def get_edr_assessments_by_alert_ids(self, edr_alert_ids: List[str]):
        response = self.request_with_refresh_expired_access_token(path='/edr-connector/notes/get-by-edr-alert-ids',
                                                                  method='GET',
                                                                  data=dict(edr_alert_ids=edr_alert_ids))

        raise_for_status(response)

        return response.json()

    @staticmethod
    def _assert_result_response(ignore_not_found: bool, response: Response):
        statuses_to_ignore = [HTTPStatus.NOT_FOUND] if ignore_not_found else None
        raise_for_status(response, statuses_to_ignore=statuses_to_ignore)

    @staticmethod
    def _param_initialize(disable_dynamic_unpacking: bool,
                          disable_static_unpacking: bool,
                          code_item_type: str = None,
                          zip_password: str = None,
                          sandbox_command_line_arguments: str = None,
                          **additional_parameters):
        data = {}

        if disable_dynamic_unpacking is not None:
            data['disable_dynamic_execution'] = disable_dynamic_unpacking
        if disable_static_unpacking is not None:
            data['disable_static_extraction'] = disable_static_unpacking
        if code_item_type:
            data['code_item_type'] = code_item_type
        if zip_password:
            data['zip_password'] = zip_password
        if sandbox_command_line_arguments:
            data['sandbox_command_line_arguments'] = sandbox_command_line_arguments

        data.update(additional_parameters)

        return data

    @staticmethod
    def _assert_analysis_response_status_code(response: Response):
        if response.status_code == HTTPStatus.NOT_FOUND:
            raise errors.HashDoesNotExistError(response)
        elif response.status_code == HTTPStatus.CONFLICT:
            running_analysis_id = response.json().get('result', {}).get('analysis_id')
            raise errors.AnalysisIsAlreadyRunningError(response, running_analysis_id)
        elif response.status_code == HTTPStatus.FORBIDDEN:
            raise errors.InsufficientQuotaError(response)
        elif response.status_code == HTTPStatus.BAD_REQUEST:
            data = response.json()
            error = data.get('error', '')
            raise errors.ServerError('Server returned bad request error: {}'.format(error), response)
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

    def assert_on_premise_above_v21_11(self):
        if self.on_premise_version and self.on_premise_version <= OnPremiseVersion.V21_11:
            raise errors.UnsupportedOnPremiseVersionError('This endpoint is not available yet on this on-premise')

    def assert_on_premise_above_v22_10(self):
        if self.on_premise_version and self.on_premise_version <= OnPremiseVersion.V22_10:
            raise errors.UnsupportedOnPremiseVersionError('This endpoint is not available yet on this on-premise')

    def assert_any_on_premise(self):
        if self.on_premise_version:
            raise errors.UnsupportedOnPremiseVersionError('This endpoint is not available yet on on-premise')


def get_global_api() -> IntezerApi:
    global _global_api

    if not _global_api:
        raise errors.GlobalApiIsNotInitializedError()

    return _global_api


def set_global_api(api_key: str = None,
                   api_version: str = None,
                   base_url: str = None,
                   verify_ssl: bool = True,
                   on_premise_version: OnPremiseVersion = None):
    global _global_api
    api_key = api_key or os.environ.get('INTEZER_ANALYZE_API_KEY')
    _global_api = IntezerApi(api_version or consts.API_VERSION,
                             api_key,
                             base_url or consts.BASE_URL,
                             verify_ssl,
                             on_premise_version)
