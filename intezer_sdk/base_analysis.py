import abc
import datetime
import time
from http import HTTPStatus
from typing import Any
from typing import Dict
from typing import Optional
from typing import Union

from requests import Response

from intezer_sdk import consts
from intezer_sdk import errors
from intezer_sdk.api import IntezerApi
from intezer_sdk.api import get_global_api


class Analysis(metaclass=abc.ABCMeta):
    def __init__(self, api: IntezerApi = None):
        self.status = None
        self.analysis_id = None
        self._api: IntezerApi = api or get_global_api()
        self._report: Optional[Dict[str, Any]] = None

    @abc.abstractmethod
    def _query_status_from_api(self) -> Response:
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def from_analysis_id(cls, analysis_id: str, api: IntezerApi = None):
        raise NotImplementedError()

    def wait_for_completion(self,
                            interval: int = None,
                            sleep_before_first_check=False,
                            timeout: Optional[datetime.timedelta] = None):
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

            while status_code != consts.AnalysisStatusCode.FINISHED:
                timeout_passed = timeout and datetime.datetime.utcnow() - start_time > timeout
                if timeout_passed:
                    raise TimeoutError
                time.sleep(interval)
                status_code = self.check_status()

    def _is_analysis_running(self) -> bool:
        return self.status in (consts.AnalysisStatusCode.CREATED,
                               consts.AnalysisStatusCode.IN_PROGRESS,
                               consts.AnalysisStatusCode.QUEUED)

    def check_status(self) -> consts.AnalysisStatusCode:
        if not self._is_analysis_running():
            raise errors.IntezerError('Analysis is not running')

        response = self._query_status_from_api()
        if response.status_code == HTTPStatus.OK:
            result = response.json()
            if result['status'] == consts.AnalysisStatusCode.FAILED.value:
                self.status = consts.AnalysisStatusCode.FAILED
                raise errors.IntezerError('Analysis failed')
            self._report = result['result']
            self.status = consts.AnalysisStatusCode.FINISHED
        elif response.status_code == HTTPStatus.ACCEPTED:
            self.status = consts.AnalysisStatusCode.IN_PROGRESS
        else:
            raise errors.IntezerError('Error in response status code:{}'.format(response.status_code))

        return self.status

    def result(self) -> dict:
        if self._is_analysis_running():
            raise errors.AnalysisIsStillRunningError()
        if not self._report:
            raise errors.ReportDoesNotExistError()

        return self._report

    def _set_report(self, report: dict):
        if not report:
            raise ValueError('Report can not be None')

        self.analysis_id = report['analysis_id']
        self._report = report
        self.status = consts.AnalysisStatusCode.FINISHED

    def _assert_analysis_finished(self):
        if self._is_analysis_running():
            raise errors.AnalysisIsStillRunningError()
        if self.status != consts.AnalysisStatusCode.FINISHED:
            raise errors.IntezerError('Analysis not finished successfully')

    @classmethod
    def _create_analysis_from_response(cls, response: Response, api: IntezerApi, analysis_id: str):
        if response.status_code == HTTPStatus.NOT_FOUND:
            return None

        response_json = response.json()
        status = response_json['status']
        if status == consts.AnalysisStatusCode.FAILED.value:
            raise errors.AnalysisFailedError()

        analysis = cls(api=api)
        if status != 'succeeded':
            analysis.status = consts.AnalysisStatusCode(status)
            analysis.analysis_id = analysis_id
        else:
            analysis_report = response_json.get('result')
            analysis._set_report(analysis_report)

        return analysis


class BaseAnalysis(Analysis):
    @abc.abstractmethod
    def _send_analyze_to_api(self, **additional_parameters) -> str:
        raise NotImplementedError()

    def send(self,
             wait: Union[bool, int] = False,
             wait_timeout: Optional[datetime.timedelta] = None,
             **additional_parameters) -> None:
        if self.analysis_id:
            raise errors.AnalysisHasAlreadyBeenSentError()

        self.analysis_id = self._send_analyze_to_api(**additional_parameters)

        self.status = consts.AnalysisStatusCode.CREATED

        if wait:
            if isinstance(wait, bool):
                self.wait_for_completion(sleep_before_first_check=True, timeout=wait_timeout)
            else:
                self.wait_for_completion(wait, sleep_before_first_check=True, timeout=wait_timeout)

