import time

from intezer_sdk import errors
from intezer_sdk.api import IntezerApi
from intezer_sdk.api import get_global_api
from intezer_sdk.consts import AnalysisStatusCode
from intezer_sdk.consts import CHECK_STATUS_INTERVAL

try:
    from http import HTTPStatus
except ImportError:
    import httplib as HTTPStatus


class Analysis(object):
    def __init__(self,
                 file_path=None,
                 file_hash=None,
                 dynamic_unpacking=None,
                 api=None,
                 static_unpacking=None):  # type: (str, str, bool, IntezerApi, bool) -> None
        if (file_hash is not None) == (file_path is not None):
            raise ValueError('Choose between file hash or file path analysis')

        self.status = None  # type: AnalysisStatusCode
        self.analyses_id = None  # type: str
        self._file_hash = file_hash  # type: str
        self._dynamic_unpacking = dynamic_unpacking  # type: bool
        self._static_unpacking = static_unpacking  # type: bool
        self._file_path = file_path  # type: str
        self._report = None  # type: dict
        self._api = api or get_global_api()  # type: IntezerApi

    def send(self, wait=False):  # type: (bool) -> None
        if self.analyses_id:
            raise errors.AnalysisHasAlreadyBeenSent()

        if self._file_hash:
            self.analyses_id = self._api.analyze_by_hash(self._file_hash,
                                                         self._dynamic_unpacking,
                                                         self._static_unpacking)
        else:
            self.analyses_id = self._api.analyze_by_file(self._file_path,
                                                         self._dynamic_unpacking,
                                                         self._static_unpacking)

        self.status = AnalysisStatusCode.CREATED

        if wait:
            self.wait_for_completion()

    def wait_for_completion(self):
        if self._is_analysis_running():
            status_code = self.check_status()

            while status_code != AnalysisStatusCode.FINISH:
                time.sleep(CHECK_STATUS_INTERVAL)
                status_code = self.check_status()

    def check_status(self):
        if not self._is_analysis_running():
            raise errors.IntezerError('Analysis dont running')

        response = self._api.get_analysis_response(self.analyses_id)
        if response.status_code == HTTPStatus.OK:
            self._report = response.json()['result']
            self.status = AnalysisStatusCode.FINISH
        elif response.status_code == HTTPStatus.ACCEPTED:
            self.status = AnalysisStatusCode.IN_PROGRESS
        else:
            raise errors.IntezerError('Error in response status code:{}'.format(response.status_code))

        return self.status

    def result(self):
        if self._is_analysis_running():
            raise errors.AnalysisIsStillRunning()
        if not self._report:
            raise errors.ReportDoesNotExistError()

        return self._report

    def _is_analysis_running(self):
        return self.status in (AnalysisStatusCode.CREATED, AnalysisStatusCode.IN_PROGRESS)
