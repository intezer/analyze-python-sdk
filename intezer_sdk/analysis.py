import datetime
import logging
import os
from http import HTTPStatus
from typing import BinaryIO
from typing import IO
from typing import Optional
from typing import Union

import requests
from requests import Response

from intezer_sdk import consts
from intezer_sdk import errors
from intezer_sdk import operation
from intezer_sdk._util import deprecated
from intezer_sdk.api import IntezerApi
from intezer_sdk.api import get_global_api
from intezer_sdk.base_analysis import BaseAnalysis
from intezer_sdk.sub_analysis import SubAnalysis

logger = logging.getLogger(__name__)


class FileAnalysis(BaseAnalysis):
    def __init__(self,
                 file_path: str = None,
                 file_hash: str = None,
                 file_stream: BinaryIO = None,
                 disable_dynamic_unpacking: bool = None,
                 disable_static_unpacking: bool = None,
                 api: IntezerApi = None,
                 file_name: str = None,
                 code_item_type: str = None,
                 zip_password: str = None,
                 download_url: str = None,
                 sandbox_command_line_arguments: str = None):
        super().__init__(api)
        if [file_path, file_hash, file_stream, download_url].count(None) < 3:
            raise ValueError('Choose between file hash, file stream, file path, or download from url analysis')

        if file_hash and code_item_type:
            logger.warning('Analyze by hash ignores code item type')

        if code_item_type and code_item_type not in [c.value for c in consts.CodeItemType]:
            raise ValueError('Invalid code item type, possible code item types are: file, memory module')

        # Input sources
        self._file_hash = file_hash
        self._file_path = file_path
        self._file_stream = file_stream
        self._download_url = download_url

        self._disable_dynamic_unpacking = disable_dynamic_unpacking
        self._disable_static_unpacking = disable_static_unpacking
        self._file_name = file_name
        self._code_item_type = code_item_type
        self._zip_password = zip_password
        self._sandbox_command_line_arguments = sandbox_command_line_arguments
        self._sub_analyses = None
        self._root_analysis = None
        self._iocs_report = None
        self._dynamic_ttps_report = None
        self._operations = {}

        if self._file_path and not self._file_name:
            self._file_name = os.path.basename(file_path)

        if self._zip_password:
            if self._file_name:
                if not self._file_name.endswith('.zip'):
                    self._file_name += '.zip'
            else:
                self._file_name = 'file.zip'

    @classmethod
    def from_analysis_id(cls, analysis_id: str, api: IntezerApi = None) -> Optional['FileAnalysis']:
        api = api or get_global_api()
        response = api.get_file_analysis_response(analysis_id, True)
        return cls._create_analysis_from_response(response, api, analysis_id)

    @classmethod
    def from_latest_hash_analysis(cls,
                                  file_hash: str,
                                  api: IntezerApi = None,
                                  private_only: bool = False,
                                  **additional_parameters) -> Optional['FileAnalysis']:
        api = api or get_global_api()
        analysis_report = api.get_latest_analysis(file_hash, private_only, **additional_parameters)

        if not analysis_report:
            return None

        analysis = cls(file_hash=file_hash, api=api)
        analysis._set_report(analysis_report)

        return analysis

    def _query_status_from_api(self) -> Response:
        return self._api.get_file_analysis_response(self.analysis_id, False)

    def _send_analyze_to_api(self, **additional_parameters) -> str:
        if all(param is None for param in [self._file_path, self._file_hash, self._file_stream, self._download_url]):
            raise ValueError('Choose between file hash, file stream, file path, or download from url analysis')

        if self._file_hash:
            return self._api.analyze_by_hash(self._file_hash,
                                             self._disable_dynamic_unpacking,
                                             self._disable_static_unpacking,
                                             self._sandbox_command_line_arguments,
                                             **additional_parameters)
        elif self._download_url:
            return self._api.analyze_by_download_url(
                download_url=self._download_url,
                disable_dynamic_unpacking=self._disable_dynamic_unpacking,
                disable_static_unpacking=self._disable_static_unpacking,
                code_item_type=self._code_item_type,
                zip_password=self._zip_password,
                sandbox_command_line_arguments=self._sandbox_command_line_arguments,
                **additional_parameters)
        else:
            return self._api.analyze_by_file(self._file_path,
                                             self._file_stream,
                                             disable_dynamic_unpacking=self._disable_dynamic_unpacking,
                                             disable_static_unpacking=self._disable_static_unpacking,
                                             file_name=self._file_name,
                                             code_item_type=self._code_item_type,
                                             zip_password=self._zip_password,
                                             sandbox_command_line_arguments=self._sandbox_command_line_arguments,
                                             **additional_parameters)

    def get_sub_analyses(self):
        if self._sub_analyses is None and self.analysis_id:
            self._init_sub_analyses()
        return self._sub_analyses

    def get_root_analysis(self) -> SubAnalysis:
        if self._root_analysis is None and self.analysis_id:
            self._init_sub_analyses()
        return self._root_analysis

    def _init_sub_analyses(self):
        all_sub_analysis = self._api.get_sub_analyses_by_id(self.analysis_id)
        self._sub_analyses = []
        for sub_analysis in all_sub_analysis:
            sub_analysis_object = SubAnalysis(sub_analysis['sub_analysis_id'],
                                              self.analysis_id,
                                              sub_analysis['sha256'],
                                              sub_analysis['source'],
                                              sub_analysis.get('extraction_info'),
                                              api=self._api)
            if sub_analysis_object.source == 'root':
                self._root_analysis = sub_analysis_object
            else:
                self._sub_analyses.append(sub_analysis_object)

    def download_file(self, path: str = None, output_stream: IO = None):
        """
        Downloads the analysis's file.
        `path` or `output_stream` must be provided.
        :param path: A path to where to save the file, it can be either a directory or non-existing file path.
        :param output_stream: A file-like object to write the file's content to.
        """
        self._api.download_file_by_sha256(self.result()['sha256'], path, output_stream)

    @property
    def iocs(self) -> dict:
        self._assert_analysis_finished()
        if not self._iocs_report:
            try:
                self._iocs_report = self._api.get_iocs(self.analysis_id)
            except requests.HTTPError as e:
                if e.response.status_code == HTTPStatus.NOT_FOUND:
                    self._iocs_report = None
                else:
                    raise

        return self._iocs_report

    def get_detections(self,
                       wait: Union[bool, int] = False,
                       wait_timeout: Optional[datetime.timedelta] = None) -> Optional[operation.Operation]:
        if self._api.on_premise_version:
            raise errors.UnsupportedOnPremiseVersionError("Detection isn't supported yet on on-premise")
        self._assert_analysis_finished()
        result_url = self._api.get_detection_result_url(self.analysis_id)
        if not result_url:
            return None

        return operation.handle_operation(self._operations, self._api, 'Detection', result_url, wait, wait_timeout)

    @property
    def dynamic_ttps(self) -> dict:
        self._assert_analysis_finished()
        if not self._dynamic_ttps_report:
            try:
                self._dynamic_ttps_report = self._api.get_dynamic_ttps(self.analysis_id)
            except requests.HTTPError as e:
                if e.response.status_code == HTTPStatus.NOT_FOUND:
                    self._dynamic_ttps_report = None
                else:
                    raise

        return self._dynamic_ttps_report


@deprecated('This method is deprecated, use FileAnalysis.from_latest_hash_analysis instead to be explict')
def get_latest_analysis(file_hash: str,
                        api: IntezerApi = None,
                        private_only: bool = False,
                        **additional_parameters) -> Optional[FileAnalysis]:
    return FileAnalysis.from_latest_hash_analysis(file_hash, api, private_only, **additional_parameters)


@deprecated('This method is deprecated, use FileAnalysis.from_analysis_by_id instead to be explict')
def get_file_analysis_by_id(analysis_id: str, api: IntezerApi = None) -> Optional[FileAnalysis]:
    return FileAnalysis.from_analysis_id(analysis_id, api)


@deprecated('This method is deprecated, use FileAnalysis.from_analysis_by_id instead to be explict')
def get_analysis_by_id(analysis_id: str, api: IntezerApi = None) -> Optional[FileAnalysis]:
    return get_file_analysis_by_id(analysis_id, api)


Analysis = FileAnalysis


class UrlAnalysis(BaseAnalysis):
    def __init__(self, url: Optional[str] = None, api: IntezerApi = None):
        super().__init__(api)
        self._api.assert_any_on_premise()
        self.url = url
        self._file_analysis: Optional[FileAnalysis] = None

    @classmethod
    def from_analysis_id(cls, analysis_id: str, api: IntezerApi = None) -> Optional['UrlAnalysis']:
        api = api or get_global_api()
        response = api.get_url_analysis_response(analysis_id, True)
        return cls._create_analysis_from_response(response, api, analysis_id)

    def _set_report(self, report: dict):
        super()._set_report(report)
        if not self.url:
            self.url = report['submitted_url']

    def _query_status_from_api(self) -> Response:
        return self._api.get_url_analysis_response(self.analysis_id, False)

    def _send_analyze_to_api(self, **additional_parameters) -> str:
        if not self.url:
            raise ValueError('url must be provided')
        return self._api.analyze_url(self.url, **additional_parameters)

    @property
    def downloaded_file_analysis(self) -> Optional[FileAnalysis]:
        if self.status != consts.AnalysisStatusCode.FINISHED:
            raise
        if self._file_analysis:
            return self._file_analysis

        if 'downloaded_file' not in self._report:
            return None

        file_analysis_id = self._report['downloaded_file']['analysis_id']
        self._file_analysis = get_file_analysis_by_id(file_analysis_id)
        return self._file_analysis


@deprecated('This method is deprecated, use UrlAnalysis.from_analysis_by_id instead to be explict')
def get_url_analysis_by_id(analysis_id: str, api: IntezerApi = None) -> Optional[UrlAnalysis]:
    return UrlAnalysis.from_analysis_id(analysis_id, api)
