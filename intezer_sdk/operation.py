import time

import typing

from intezer_sdk.api import IntezerApi
from intezer_sdk.api import get_global_api
from intezer_sdk.consts import CHECK_STATUS_INTERVAL
from intezer_sdk.consts import OperationStatusCode
from intezer_sdk import errors, consts

from http import HTTPStatus


class BaseOperation:
    def __init__(self, url: str, wait: typing.Union[bool, int], api: IntezerApi = None):
        self.status = OperationStatusCode.IN_PROGRESS
        self.url = url
        self.result = None
        self._api = api or get_global_api()

        if wait:
            if isinstance(wait, int):
                self._wait_for_completion(wait, sleep_before_first_check=True)
            else:
                self._wait_for_completion(sleep_before_first_check=True)

    def _wait_for_completion(self, interval: int = None, sleep_before_first_check=False) -> None:
        if not interval:
            interval = CHECK_STATUS_INTERVAL

        if sleep_before_first_check:
            time.sleep(interval)
        operation_result = self._api.get_url_result(self.url)

        while not handle_response_status(operation_result.status_code):
            time.sleep(interval)
            operation_result = self._api.get_url_result(self.url)

        self.status = OperationStatusCode.FINISH
        self.result = operation_result.json()['result']


class Operation(BaseOperation):
    def get_result(self):
        if self.status != OperationStatusCode.FINISH:

            operation_result = self._api.get_url_result(self.url)

            if handle_response_status(operation_result.status_code):
                self.result = operation_result.json()['result']
                self.status = OperationStatusCode.FINISH
            else:
                raise errors.OperationStillRunning('operation')
        return self.result


class PaginatedOperation(BaseOperation):
    def __init__(self, url: str, wait: typing.Union[bool, int], api: IntezerApi = None):
        super().__init__(url, wait, api)
        self._current_offset = 0
        self._current_limit = 0

    def fetch_next(self, limit: int = consts.DEFAULT_FAMILY_FILES_LIMIT):
        if self.status != OperationStatusCode.FINISH:
            raise errors.OperationStillRunning('Fetching current files')

        if self.result:
            if len(self.result) < self._current_limit:
                raise errors.EndOfData()

            self._current_offset = self._current_offset + self._current_limit

        self._current_limit = limit
        offset_data = {'offset': self._current_offset, 'limit': self._current_limit}

        operation_result = self._api.get_url_result(self.url, offset_data)

        if handle_response_status(operation_result.status_code):
            self.result = operation_result.json()['result']
            self.status = OperationStatusCode.FINISH
        else:
            raise errors.OperationStillRunning('operation')

        return self.result


def handle_response_status(status):
    if status not in (HTTPStatus.OK, HTTPStatus.ACCEPTED):
        raise errors.IntezerError('Error in response status code:{}'.format(status))

    return status == HTTPStatus.OK
