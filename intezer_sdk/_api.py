import os
from http import HTTPStatus
from typing import Any
from typing import BinaryIO
from typing import Dict
from typing import IO
from typing import List
from typing import Optional

from requests import Response

from intezer_sdk import consts
from intezer_sdk import errors
from intezer_sdk._util import deprecated
from intezer_sdk.api import IntezerApiClient
from intezer_sdk.api import raise_for_status
from intezer_sdk.consts import IndexType
from intezer_sdk.consts import OnPremiseVersion


class IntezerApi:
    def __init__(self, api: IntezerApiClient):
        self.api = api

    @property
    def on_premise_version(self) -> Optional[OnPremiseVersion]:
        return self.api.on_premise_version

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
        response = self.api.request_with_refresh_expired_access_token('POST', '/analyze-by-hash', data)
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
        response = self.api.request_with_refresh_expired_access_token('POST', '/analyze-by-url', data)
        self._assert_analysis_response_status_code(response)

        return self._get_analysis_id_from_response(response)

    def _analyze_file_stream(self, file_stream: BinaryIO, file_name: str, options: dict) -> str:
        file = {'file': (file_name, file_stream)}

        response = self.api.request_with_refresh_expired_access_token('POST', '/analyze', options, files=file)
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
                            composed_only: bool = False,
                            **additional_parameters) -> Optional[dict]:

        options = {**additional_parameters}
        if not self.api.on_premise_version or self.api.on_premise_version > OnPremiseVersion.V21_11:
            options['should_get_only_private_analysis']= private_only
        if not self.api.on_premise_version or self.api.on_premise_version > OnPremiseVersion.V22_10:
            options['should_get_only_composed_analysis']= composed_only

        response = self.api.request_with_refresh_expired_access_token('GET', f'/files/{file_hash}', options)

        if response.status_code == HTTPStatus.NOT_FOUND:
            return None

        raise_for_status(response)

        return response.json()['result']

    def get_file_analysis_response(self, analyses_id: str, ignore_not_found: bool) -> Response:
        response = self.api.request_with_refresh_expired_access_token('GET', f'/analyses/{analyses_id}')
        self._assert_result_response(ignore_not_found, response)

        return response

    @deprecated('This method is deprecated, use get_file_analysis_response instead to be explict')
    def get_analysis_response(self, analyses_id: str) -> Response:
        return self.get_file_analysis_response(analyses_id, False)

    def get_url_analysis_response(self, analyses_id: str, ignore_not_found: bool) -> Response:
        response = self.api.request_with_refresh_expired_access_token('GET', f'/url/{analyses_id}')
        self._assert_result_response(ignore_not_found, response)

        return response

    def get_endpoint_analysis_response(self, analyses_id: str, ignore_not_found: bool) -> Response:
        response = self.api.request_with_refresh_expired_access_token('GET', f'/endpoint-analyses/{analyses_id}')
        self._assert_result_response(ignore_not_found, response)

        return response

    def get_endpoint_sub_analyses(self, analyses_id: str, verdicts: Optional[List[str]]) -> List[dict]:
        data = dict(verdicts=verdicts) if verdicts is not None else None
        response = self.api.request_with_refresh_expired_access_token(
            'GET',
            f'/endpoint-analyses/{analyses_id}/sub-analyses',
            data
        )
        self._assert_result_response(False, response)

        return response.json()['sub_analyses']

    def create_endpoint_scan(self, scanner_info: dict) -> Dict[str, str]:
        if not self.api.on_premise_version or self.api.on_premise_version > OnPremiseVersion.V22_10:
            scanner_info['scan_type'] = consts.SCAN_TYPE_OFFLINE_ENDPOINT_SCAN
        response = self.api.request_with_refresh_expired_access_token('POST',
                                                                            'scans',
                                                                      scanner_info,
                                                                      base_url=self.api.base_url)

        raise_for_status(response)
        return response.json()['result']

    def get_iocs(self, analyses_id: str) -> Optional[dict]:
        response = self.api.request_with_refresh_expired_access_token('GET', f'/analyses/{analyses_id}/iocs')
        raise_for_status(response)

        return response.json()['result']

    def get_detection_result_url(self, analyses_id: str) -> Optional[str]:
        response = self.api.request_with_refresh_expired_access_token('GET', f'/analyses/{analyses_id}/detect')
        if response.status_code == HTTPStatus.CONFLICT:
            return None
        raise_for_status(response)

        return response.json()['result_url']

    def get_dynamic_ttps(self, analyses_id: str) -> Optional[dict]:
        self.assert_on_premise_above_v21_11()
        response = self.api.request_with_refresh_expired_access_token('GET',
                                                                            f'/analyses/{analyses_id}/dynamic-ttps')
        raise_for_status(response)

        return response.json()['result']

    def get_family_info(self, family_id: str) -> Optional[dict]:
        response = self.api.request_with_refresh_expired_access_token('GET', f'/families/{family_id}/info')
        if response.status_code == HTTPStatus.NOT_FOUND:
            return None

        raise_for_status(response, allowed_statuses=[HTTPStatus.OK])
        return response.json()['result']

    def get_family_by_name(self, family_name: str) -> Optional[Dict[str, Any]]:
        response = self.api.request_with_refresh_expired_access_token('GET',
                                                                            '/families',
                                                                      {'family_name': family_name})
        if response.status_code == HTTPStatus.NOT_FOUND:
            return None

        raise_for_status(response, allowed_statuses=[HTTPStatus.OK])
        return response.json()['result']

    def get_sub_analyses_by_id(self, analysis_id: str) -> Optional[List[dict]]:
        response = self.api.request_with_refresh_expired_access_token(
            'GET', f'/analyses/{analysis_id}/sub-analyses'
        )
        raise_for_status(response)

        return response.json()['sub_analyses']

    def get_sub_analysis_code_reuse_by_id(self,
                                          composed_analysis_id: str,
                                          sub_analysis_id: str) -> Optional[dict]:
        response = self.api.request_with_refresh_expired_access_token(
            'GET', f'/analyses/{composed_analysis_id}/sub-analyses/{sub_analysis_id}/code-reuse',
        )

        if response.status_code == HTTPStatus.CONFLICT:
            return None

        raise_for_status(response)

        return response.json()

    def get_sub_analysis_metadata_by_id(self, composed_analysis_id: str, sub_analysis_id: str) -> dict:
        response = self.api.request_with_refresh_expired_access_token(
            'GET', f'/analyses/{composed_analysis_id}/sub-analyses/{sub_analysis_id}/metadata'
        )
        raise_for_status(response)

        return response.json()

    def get_sub_analysis_related_files_by_family_id(self,
                                                    composed_analysis_id: str,
                                                    sub_analysis_id: str,
                                                    family_id: str) -> str:
        response = self.api.request_with_refresh_expired_access_token(
            'POST',
            f'/analyses/{composed_analysis_id}/sub-analyses/{sub_analysis_id}/code-reuse/families/{family_id}/find-related-files'
        )

        raise_for_status(response)

        return response.json()['result_url']

    def get_sub_analysis_account_related_samples_by_id(self, composed_analysis_id: str, sub_analysis_id: str) -> str:
        response = self.api.request_with_refresh_expired_access_token(
            'POST', f'/analyses/{composed_analysis_id}/sub-analyses/{sub_analysis_id}/get-account-related-samples'
        )

        raise_for_status(response)

        return response.json()['result_url']

    def get_sub_analysis_capabilities_by_id(self, composed_analysis_id: str, sub_analysis_id: str) -> str:
        self.assert_on_premise_above_v21_11()
        response = self.api.request_with_refresh_expired_access_token(
            'POST', f'/analyses/{composed_analysis_id}/sub-analyses/{sub_analysis_id}/capabilities',
        )

        raise_for_status(response)

        return response.json()['result_url']

    def generate_sub_analysis_vaccine_by_id(self, composed_analysis_id: str, sub_analysis_id: str) -> str:
        response = self.api.request_with_refresh_expired_access_token(
            'POST', f'/analyses/{composed_analysis_id}/sub-analyses/{sub_analysis_id}/generate-vaccine')

        raise_for_status(response)

        return response.json()['result_url']

    def get_strings_by_id(self, composed_analysis_id: str, sub_analysis_id: str) -> dict:
        response = self.api.request_with_refresh_expired_access_token(
            'POST', f'/analyses/{composed_analysis_id}/sub-analyses/{sub_analysis_id}/strings'
        )

        raise_for_status(response)

        return response.json()

    def get_string_related_samples_by_id(self,
                                         composed_analysis_id: str,
                                         sub_analysis_id: str,
                                         string_value: str) -> str:
        response = self.api.request_with_refresh_expired_access_token(
            'POST',
            f'/analyses/{composed_analysis_id}/sub-analyses/{sub_analysis_id}/string-related-samples',
            {'string_value': string_value}
        )

        raise_for_status(response)

        return response.json()['result_url']

    def get_url_result(self, url: str) -> dict:
        response = self.api.request_with_refresh_expired_access_token('GET', url)

        raise_for_status(response)
        result = response.json()

        if 'error' in result:
            raise errors.IntezerError(f'response error: {result["error"]}')

        return result

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

        response = self.api.request_with_refresh_expired_access_token('GET',
                                                                            f'/files/{sha256}/download',
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

        response = self.api.request_with_refresh_expired_access_token('POST', f'/files/{sha256}/index', data)
        self._assert_index_response_status_code(response)

        return self._get_index_id_from_response(response)

    def index_by_file(self, file_path: str, index_as: IndexType, family_name: str = None) -> Response:
        data = {'index_as': index_as.value}
        if family_name:
            data['family_name'] = family_name

        with open(file_path, 'rb') as file_to_upload:
            file = {'file': (os.path.basename(file_path), file_to_upload)}

            response = self.api.request_with_refresh_expired_access_token('POST',
                                                                                '/files/index',
                                                                          data,
                                                                          files=file)

        self._assert_index_response_status_code(response)

        return self._get_index_id_from_response(response)

    def get_index_response(self, index_id: str) -> Response:
        response = self.api.request_with_refresh_expired_access_token('GET', f'/files/index/{index_id}')
        raise_for_status(response)

        return response

    def analyze_url(self, url: str, **additional_parameters) -> Optional[str]:
        self.assert_any_on_premise()
        response = self.api.request_with_refresh_expired_access_token('POST',
                                                                            '/url',
                                                                      dict(url=url, **additional_parameters))
        self._assert_analysis_response_status_code(response)

        return self._get_analysis_id_from_response(response)

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
            raise errors.ServerError(f'Server returned bad request error: {error}', response)
        elif response.status_code != HTTPStatus.CREATED:
            raise errors.ServerError(f'Error in response status code:{response.status_code}', response)

    @staticmethod
    def _assert_index_response_status_code(response: Response):
        if response.status_code == HTTPStatus.NOT_FOUND:
            raise errors.HashDoesNotExistError(response)
        elif response.status_code != HTTPStatus.CREATED:
            raise errors.ServerError(f'Error in response status code:{response.status_code}', response)

    @staticmethod
    def _get_analysis_id_from_response(response: Response):
        return response.json()['result_url'].split('/')[2]

    @staticmethod
    def _get_index_id_from_response(response: Response):
        return response.json()['result_url'].split('/')[3]

    def assert_on_premise_above_v21_11(self):
        if self.api.on_premise_version and self.api.on_premise_version <= OnPremiseVersion.V21_11:
            raise errors.UnsupportedOnPremiseVersionError('This endpoint is not available yet on this on-premise')

    def assert_on_premise_above_v22_10(self):
        if self.api.on_premise_version and self.api.on_premise_version <= OnPremiseVersion.V22_10:
            raise errors.UnsupportedOnPremiseVersionError('This endpoint is not available yet on this on-premise')

    def assert_any_on_premise(self):
        if self.api.on_premise_version:
            raise errors.UnsupportedOnPremiseVersionError('This endpoint is not available yet on on-premise')
