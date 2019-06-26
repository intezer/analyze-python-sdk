import time
import typing

from intezer_sdk import consts
from intezer_sdk import errors
from intezer_sdk.api import IntezerApi
from intezer_sdk.api import get_global_api

try:
    from http import HTTPStatus
except ImportError:
    import httplib as HTTPStatus


class Analysis(object):
    def __init__(self,
                 file_path: str = None,
                 file_hash: str = None,
                 file_stream: typing.BinaryIO = None,
                 dynamic_unpacking: bool = None,
                 api: IntezerApi = None,
                 static_unpacking: bool = None) -> None:
        if [file_path, file_hash, file_stream].count(None) != 2:
            raise ValueError('Choose between file hash, file stream or file path analysis')

        self.status = None
        self.analysis_id = None
        self._file_hash = file_hash
        self._dynamic_unpacking = dynamic_unpacking
        self._static_unpacking = static_unpacking
        self._file_path = file_path
        self._file_stream = file_stream
        self._report = None
        self._api = api or get_global_api()

    def send(self, wait: bool = False) -> None:
        if self.analysis_id:
            raise errors.AnalysisHasAlreadyBeenSent()

        if self._file_hash:
            self.analysis_id = self._api.analyze_by_hash(self._file_hash,
                                                         self._dynamic_unpacking,
                                                         self._static_unpacking)
        else:
            self.analysis_id = self._api.analyze_by_file(self._file_path,
                                                         self._file_stream,
                                                         dynamic_unpacking=self._dynamic_unpacking,
                                                         static_unpacking=self._static_unpacking)

        self.status = consts.AnalysisStatusCode.CREATED

        if wait:
            self.wait_for_completion()

    def wait_for_completion(self):
        if self._is_analysis_running():
            status_code = self.check_status()

            while status_code != consts.AnalysisStatusCode.FINISH:
                time.sleep(consts.CHECK_STATUS_INTERVAL)
                status_code = self.check_status()

    def check_status(self):
        if not self._is_analysis_running():
            raise errors.IntezerError('Analysis dont running')

        response = self._api.get_analysis_response(self.analysis_id)
        if response.status_code == HTTPStatus.OK:
            self._report = response.json()['result']
            self.status = consts.AnalysisStatusCode.FINISH
        elif response.status_code == HTTPStatus.ACCEPTED:
            self.status = consts.AnalysisStatusCode.IN_PROGRESS
        else:
            raise errors.IntezerError('Error in response status code:{}'.format(response.status_code))

        return self.status

    def result(self):
        if self._is_analysis_running():
            raise errors.AnalysisIsStillRunning()
        if not self._report:
            raise errors.ReportDoesNotExistError()

        return self._report

    def set_report(self, report: dict):
        if not report:
            raise ValueError('Report can not be None')

        self.analysis_id = report['analysis_id']
        self._report = report
        self.status = consts.AnalysisStatusCode.FINISH

    def _is_analysis_running(self):
        return self.status in (consts.AnalysisStatusCode.CREATED, consts.AnalysisStatusCode.IN_PROGRESS)


def get_latest_analysis(file_hash: str, api: IntezerApi = None) -> typing.Optional[Analysis]:
    api = api or get_global_api()
    analysis_report = api.get_latest_analysis(file_hash)

    if not analysis_report:
        return None

    analysis = Analysis(file_hash=file_hash, api=api)
    analysis.set_report(analysis_report)

    return analysis
