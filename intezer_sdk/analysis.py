try:
    from http import HTTPStatus
except ImportError:
    import httplib as HTTPStatus

import time

from intezer_sdk.api import IntezerApi
from intezer_sdk.consts import AnalysisStatusCode
from intezer_sdk.exceptions import AnalysisAlreadyBeenSent
from intezer_sdk.exceptions import IntezerError
from intezer_sdk.exceptions import ReportDoesNotExistError


class Analysis(object):
    def __init__(self,
                 file_path=None,  # type: str
                 file_hash=None,  # type: str
                 dynamic_unpacking=None,  # type: bool
                 api=None,  # type: IntezerApi
                 static_unpacking=None  # type: bool
                 ):
        if (file_hash is not None) == (file_path is not None):
            raise ValueError('Choose between file or sha256 analysis')

        self.status = None  # type: AnalysisStatusCode
        self.analyses_id = None  # type: str
        self._file_hash = file_hash  # type: str
        self._dynamic_unpacking = dynamic_unpacking  # type: bool
        self._static_unpacking = static_unpacking  # type: bool
        self._file_path = file_path  # type: str
        self._report = None  # type: dict
        self._api = api or IntezerApi()  # type: IntezerApi

    def send(self, wait=False):
        if self.analyses_id:
            raise AnalysisAlreadyBeenSent()

        if self._file_hash:
            self.analyses_id = self._api.analyze_by_hash(self._file_hash, self._dynamic_unpacking,
                                                         self._static_unpacking)
        else:
            with open(self._file_path, 'rb') as file_to_upload:
                files = {'file': ('file_name', file_to_upload)}
                self.analyses_id = self._api.analyze_by_files(files, self._dynamic_unpacking, self._static_unpacking)

        self.status = AnalysisStatusCode.send

        if wait:
            self.wait_for_completion()

    def wait_for_completion(self):
        if self.status in [AnalysisStatusCode.send, AnalysisStatusCode.in_progress]:
            status_code = self.check_status()

            while status_code != AnalysisStatusCode.finish:
                time.sleep(1)
                status_code = self.check_status()

    def check_status(self):
        if self.status not in [AnalysisStatusCode.send, AnalysisStatusCode.in_progress]:
            raise IntezerError()

        response = self._api.get_analysis_response(self.analyses_id)
        if response.status_code == HTTPStatus.OK:
            self._report = response.json()['result']
            self.status = AnalysisStatusCode.finish
        elif response.status_code == HTTPStatus.ACCEPTED:
            self.status = AnalysisStatusCode.in_progress
        else:
            raise IntezerError()

        return self.status

    def result(self):
        if not self._report:
            raise ReportDoesNotExistError()

        return self._report
