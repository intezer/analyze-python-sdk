import abc
import datetime
import time
import typing
from http import HTTPStatus

from requests import Response

from intezer_sdk import consts
from intezer_sdk import errors
from intezer_sdk.api import IntezerApi
from intezer_sdk.api import get_global_api


class BaseAnalysis:
    def __init__(self, api: IntezerApi = None):
        self.status = None
        self.analysis_id = None
        self._api = api or get_global_api()
        self._report: typing.Optional[typing.Dict[str, typing.Any]] = None

    @abc.abstractmethod
    def _query_status_from_api(self) -> Response:
        raise NotImplementedError()

    @abc.abstractmethod
    def _send_analyze_to_api(self, **additional_parameters) -> str:
        raise NotImplementedError()

    def wait_for_completion(self,
                            interval: int = None,
                            sleep_before_first_check=False,
                            timeout: typing.Optional[datetime.timedelta] = None):
        """
        Blocks until the analysis is completed
        :param interval: The interval to wait between checks
        :param sleep_before_first_check: Whether to sleep before the first status check
        :param timeout: Maximum duration to wait for analysis completion
        """
        start_time = datetime.datetime.utcnow()
        if not interval:
            interval = consts.CHECK_STATUS_INTERVAL
        if self._is_analysis_running():
            if sleep_before_first_check:
                time.sleep(interval)
            status_code = self.check_status()

            while status_code != consts.AnalysisStatusCode.FINISH:
                timeout_passed = timeout and datetime.datetime.utcnow() - start_time > timeout
                if timeout_passed:
                    raise TimeoutError
                time.sleep(interval)
                status_code = self.check_status()

    def _is_analysis_running(self):
        return self.status in (consts.AnalysisStatusCode.CREATED, consts.AnalysisStatusCode.IN_PROGRESS)

    def send(self,
             wait: typing.Union[bool, int] = False,
             wait_timeout: typing.Optional[datetime.timedelta] = None,
             **additional_parameters) -> None:
        if self.analysis_id:
            raise errors.AnalysisHasAlreadyBeenSent()

        self.analysis_id = self._send_analyze_to_api(**additional_parameters)

        self.status = consts.AnalysisStatusCode.CREATED

        if wait:
            if isinstance(wait, int):
                self.wait_for_completion(wait, sleep_before_first_check=True, timeout=wait_timeout)
            else:
                self.wait_for_completion(sleep_before_first_check=True, timeout=wait_timeout)

    def check_status(self):
        if not self._is_analysis_running():
            raise errors.IntezerError('FileAnalysis is not running')

        response = self._query_status_from_api()
        if response.status_code == HTTPStatus.OK:
            result = response.json()
            if result['status'] == consts.AnalysisStatusCode.FAILED.value:
                self.status = consts.AnalysisStatusCode.FAILED
                raise errors.IntezerError('Analysis failed')
            self._report = result['result']
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

    def _assert_analysis_finished(self):
        if self._is_analysis_running():
            raise errors.AnalysisIsStillRunning()
        if self.status != consts.AnalysisStatusCode.FINISH:
            raise errors.IntezerError('FileAnalysis not finished successfully')
