import time

from intezer_sdk.api import IntezerApi
from intezer_sdk.api import get_global_api
from intezer_sdk.consts import CHECK_STATUS_INTERVAL
from intezer_sdk.consts import AnalysisStatusCode
from intezer_sdk import errors

from http import HTTPStatus


class Operation:

    def __init__(self, status: AnalysisStatusCode, url: str, api: IntezerApi = None):
        self.status = status
        self.url = url
        self.result = None
        self._api = api or get_global_api()

    def get_result(self):
        if self.status != AnalysisStatusCode.FINISH:

            operation_result = self._api.get_url_result(self.url)

            if handle_response_status(operation_result.status_code):
                self.result = operation_result.json()['result']
                self.status = AnalysisStatusCode.FINISH
            else:
                raise errors.SubAnalysisOperationStillRunning('operation')
        return self.result

    def wait_for_completion(self, interval: int = None, sleep_before_first_check=False) -> None:
        if not interval:
            interval = CHECK_STATUS_INTERVAL

        if sleep_before_first_check:
            time.sleep(interval)
        operation_result = self._api.get_url_result(self.url)

        while not handle_response_status(operation_result.status_code):
            time.sleep(interval)
            operation_result = self._api.get_url_result(self.url)

        self.status = AnalysisStatusCode.FINISH
        self.result = operation_result.json()['result']


def handle_response_status(status):
    if status not in (HTTPStatus.OK, HTTPStatus.ACCEPTED):
        raise errors.IntezerError('Error in response status code:{}'.format(status))

    return status == HTTPStatus.OK
