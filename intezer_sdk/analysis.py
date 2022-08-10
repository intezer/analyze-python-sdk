import logging
import os
from http import HTTPStatus
from typing import BinaryIO
from typing import IO
from typing import Optional

import requests
from requests import Response

from intezer_sdk import consts
from intezer_sdk import errors
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
                 zip_password: str = None):
        super().__init__(api)

        if [file_path, file_hash, file_stream].count(None) != 2:
            raise ValueError('Choose between file hash, file stream or file path analysis')

        if file_hash and code_item_type:
            logger.warning('Analyze by hash ignores code item type')

        if code_item_type and code_item_type not in [c.value for c in consts.CodeItemType]:
            raise ValueError('Invalid code item type, possible code item types are: file, memory module')

        self._file_hash = file_hash
        self._disable_dynamic_unpacking = disable_dynamic_unpacking
        self._disable_static_unpacking = disable_static_unpacking
        self._file_path = file_path
        self._file_stream = file_stream
        self._file_name = file_name
        self._code_item_type = code_item_type
        self._zip_password = zip_password
        self._sub_analyses = None
        self._root_analysis = None
        self._iocs_report = None
        self._dynamic_ttps_report = None

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
        if response.status_code == HTTPStatus.NOT_FOUND:
            return None
        response_json = response.json()

        _assert_analysis_status(response_json)

        analysis_report = response_json.get('result')
        if not analysis_report:
            return None

        analysis = cls(file_hash=analysis_report['sha256'], api=api)
        analysis._set_report(analysis_report)

        return analysis

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
        if self._file_hash:
            return self._api.analyze_by_hash(self._file_hash,
                                             self._disable_dynamic_unpacking,
                                             self._disable_static_unpacking,
                                             **additional_parameters)
        else:
            return self._api.analyze_by_file(self._file_path,
                                             self._file_stream,
                                             disable_dynamic_unpacking=self._disable_dynamic_unpacking,
                                             disable_static_unpacking=self._disable_static_unpacking,
                                             file_name=self._file_name,
                                             code_item_type=self._code_item_type,
                                             zip_password=self._zip_password,
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
    def __init__(self, url: str, api: IntezerApi = None):
        super().__init__(api)
        self._api.assert_on_premise_above_v21_11()
        self.url = url
        self._file_analysis: Optional[FileAnalysis] = None

    @classmethod
    def from_analysis_id(cls, analysis_id: str, api: IntezerApi = None) -> Optional['UrlAnalysis']:
        api = api or get_global_api()
        response = api.get_url_analysis_response(analysis_id, True)
        if response.status_code == HTTPStatus.NOT_FOUND:
            return None

        response_json = response.json()
        _assert_analysis_status(response_json)

        analysis_report = response_json.get('result')
        if not analysis_report:
            return None

        analysis = UrlAnalysis(analysis_report['submitted_url'], api=api)
        analysis._set_report(analysis_report)

        return analysis

    def _query_status_from_api(self) -> Response:
        return self._api.get_url_analysis_response(self.analysis_id, False)

    def _send_analyze_to_api(self, **additional_parameters) -> str:
        return self._api.analyze_url(self.url, **additional_parameters)

    @property
    def downloaded_file_analysis(self) -> Optional[FileAnalysis]:
        if self.status != consts.AnalysisStatusCode.FINISH:
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


def _assert_analysis_status(response: dict):
    if response['status'] in (consts.AnalysisStatusCode.IN_PROGRESS.value,
                              consts.AnalysisStatusCode.QUEUED.value):
        raise errors.AnalysisIsStillRunningError()
    if response['status'] == consts.AnalysisStatusCode.FAILED.value:
        raise errors.AnalysisFailedError()
