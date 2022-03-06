import datetime
import typing

from requests import HTTPError

from intezer_sdk.api import IntezerApi
from intezer_sdk.api import get_global_api
from intezer_sdk.consts import AnalysisStatusCode
from intezer_sdk.operation import Operation


class SubAnalysis:
    def __init__(self, analysis_id: str, composed_analysis_id: str, sha256: str, source: str, api: IntezerApi = None):
        self.composed_analysis_id = composed_analysis_id
        self.analysis_id = analysis_id
        self.sha256 = sha256
        self.source = source
        self._api = api or get_global_api()
        self._code_reuse = None
        self._metadata = None
        self._capabilities = None
        self._operations = {}

    @property
    def code_reuse(self):
        if self._code_reuse is None:
            self._code_reuse = self._api.get_sub_analysis_code_reuse_by_id(self.composed_analysis_id, self.analysis_id)
        return self._code_reuse

    @property
    def metadata(self):
        if self._metadata is None:
            self._metadata = self._api.get_sub_analysis_metadata_by_id(self.composed_analysis_id, self.analysis_id)
        return self._metadata

    def find_related_files(self,
                           family_id: str,
                           wait: typing.Union[bool, int] = False,
                           wait_timeout: typing.Optional[datetime.timedelta] = None) -> Operation:
        result_url = self._api.get_sub_analysis_related_files_by_family_id(self.composed_analysis_id,
                                                                           self.analysis_id,
                                                                           family_id)
        return self._handle_operation(family_id, result_url, wait, wait_timeout)

    def get_account_related_samples(self,
                                    wait: typing.Union[bool, int] = False,
                                    wait_timeout: typing.Optional[datetime.timedelta] = None) -> typing.Optional[Operation]:
        try:
            result_url = self._api.get_sub_analysis_account_related_samples_by_id(self.composed_analysis_id,
                                                                                  self.analysis_id)
        except Exception:
            return None

        return self._handle_operation('Account related samples', result_url, wait, wait_timeout)

    def generate_vaccine(self,
                         wait: typing.Union[bool, int] = False,
                         wait_timeout: typing.Optional[datetime.timedelta] = None) -> Operation:
        result_url = self._api.generate_sub_analysis_vaccine_by_id(self.composed_analysis_id, self.analysis_id)
        return self._handle_operation('Vaccine', result_url, wait, wait_timeout)

    def get_capabilities(self,
                         wait: typing.Union[bool, int] = False,
                         wait_timeout: typing.Optional[datetime.timedelta] = None) -> Operation:
        result_url = self._api.get_sub_analysis_capabilities_by_id(self.composed_analysis_id, self.analysis_id)
        return self._handle_operation('Capabilities', result_url, wait, wait_timeout)

    def get_strings(self,
                    wait: typing.Union[bool, int] = False,
                    wait_timeout: typing.Optional[datetime.timedelta] = None) -> Operation:
        result_url = self._api.get_strings_by_id(self.composed_analysis_id, self.analysis_id)
        return self._handle_operation('Strings', result_url, wait, wait_timeout)

    def get_string_related_samples(self,
                                   string_value: str,
                                   wait: typing.Union[bool, int] = False,
                                   wait_timeout: typing.Optional[datetime.timedelta] = None) -> Operation:
        result_url = self._api.get_string_related_samples_by_id(self.composed_analysis_id,
                                                                self.analysis_id,
                                                                string_value)
        return self._handle_operation(string_value, result_url, wait, wait_timeout)

    def _handle_operation(self,
                          operation: str,
                          url: str,
                          wait: typing.Union[bool, int],
                          wait_timeout: typing.Optional[datetime.timedelta]) -> Operation:
        if operation not in self._operations:
            self._operations[operation] = Operation(AnalysisStatusCode.IN_PROGRESS, url, api=self._api)

            if wait:
                if isinstance(wait, int):
                    self._operations[operation].wait_for_completion(wait,
                                                                    sleep_before_first_check=True,
                                                                    wait_timeout=wait_timeout)
                else:
                    self._operations[operation].wait_for_completion(sleep_before_first_check=True,
                                                                    wait_timeout=wait_timeout)

        return self._operations[operation]

    def download_file(self, path: str):
        self._api.download_file_by_sha256(self.sha256, path)
