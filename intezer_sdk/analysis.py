import time

from intezer_sdk.api import IntezerApi
from intezer_sdk.api import get_global_api
from intezer_sdk.consts import analysis_status_code
from intezer_sdk.errors import AnalysisHasAlreadyBeenSent
from intezer_sdk.errors import IntezerError
from intezer_sdk.errors import ReportDoesNotExistError

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

        self.status = None  # type: analysis_status_code
        self.analyses_id = None  # type: str
        self._file_hash = file_hash  # type: str
        self._dynamic_unpacking = dynamic_unpacking  # type: bool
        self._static_unpacking = static_unpacking  # type: bool
        self._file_path = file_path  # type: str
        self._report = None  # type: dict
        self._api = api or get_global_api()  # type: IntezerApi

    def send(self, wait=False):  # type: (bool) -> None
        if self.analyses_id:
            raise AnalysisHasAlreadyBeenSent()

        if self._file_hash:
            self.analyses_id = self._api.analyze_by_hash(self._file_hash,
                                                         self._dynamic_unpacking,
                                                         self._static_unpacking)
        else:

            self.analyses_id = self._api.analyze_by_file(self._file_path,
                                                         self._dynamic_unpacking,
                                                         self._static_unpacking)

        self.status = analysis_status_code.SENT

        if wait:
            self.wait_for_completion()

    def wait_for_completion(self):
        if self.status in (analysis_status_code.SENT, analysis_status_code.IN_PROGRESS):
            status_code = self.check_status()

            while status_code != analysis_status_code.FINISH:
                time.sleep(1)
                status_code = self.check_status()

    def check_status(self):
        if self.status not in (analysis_status_code.SENT, analysis_status_code.IN_PROGRESS):
            raise IntezerError('Analysis is not in process')

        response = self._api.get_analysis_response(self.analyses_id)
        if response.status_code == HTTPStatus.OK:
            self._report = response.json()['result']
            self.status = analysis_status_code.FINISH
        elif response.status_code == HTTPStatus.ACCEPTED:
            self.status = analysis_status_code.IN_PROGRESS
        else:
            raise IntezerError('Getting wrong server code from server:{0}'.format(response.status_code))

        return self.status

    def result(self):
        if not self._report:
            raise ReportDoesNotExistError()

        return self._report
