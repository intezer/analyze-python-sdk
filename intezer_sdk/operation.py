import datetime
import time
from typing import Dict
from typing import Optional
from typing import Union

from intezer_sdk.api import IntezerApi
from intezer_sdk.api import get_global_api
from intezer_sdk.consts import CHECK_STATUS_INTERVAL
from intezer_sdk.consts import AnalysisStatusCode
from intezer_sdk import errors

from http import HTTPStatus


class Operation:

    def __init__(self, status: AnalysisStatusCode, url: str, name: str, api: IntezerApi = None):
        self.status = status
        self.url = url
        self.result = None
        self.name = name
        self._api = api or get_global_api()

    def get_result(self):
        if self.status != AnalysisStatusCode.FINISHED:
            if not self.check_status():
                raise errors.SubAnalysisOperationStillRunningError(self.name)
        return self.result

    def check_status(self) -> bool:
        operation_result = self._api.get_url_result(self.url)

        if handle_response_status(operation_result.status_code):
            self.result = operation_result.json()['result']
            self.status = AnalysisStatusCode.FINISHED
            return True

        return False

    def wait_for_completion(self,
                            interval: int = None,
                            sleep_before_first_check=False,
                            wait_timeout: Optional[datetime.timedelta] = None) -> None:
        start_time = datetime.datetime.utcnow()
        if not interval:
            interval = CHECK_STATUS_INTERVAL

        if sleep_before_first_check:
            time.sleep(interval)

        while not self.check_status():
            timeout_passed = wait_timeout and datetime.datetime.utcnow() - start_time > wait_timeout
            if timeout_passed:
                raise TimeoutError
            time.sleep(interval)


def handle_response_status(status):
    if status not in (HTTPStatus.OK, HTTPStatus.ACCEPTED):
        raise errors.IntezerError('Error in response status code:{}'.format(status))

    return status == HTTPStatus.OK


def handle_operation(operations: Dict[str, Operation],
                     api: IntezerApi,
                     operation: str,
                     result_url: str,
                     wait: Union[bool, int],
                     wait_timeout: Optional[datetime.timedelta]) -> Operation:
    if operation not in operations:
        operations[operation] = Operation(AnalysisStatusCode.IN_PROGRESS, result_url, operation, api=api)

        if wait:
            if isinstance(wait, bool):
                operations[operation].wait_for_completion(sleep_before_first_check=True,
                                                          wait_timeout=wait_timeout)
            else:
                operations[operation].wait_for_completion(wait,
                                                          sleep_before_first_check=True,
                                                          wait_timeout=wait_timeout)

    return operations[operation]
