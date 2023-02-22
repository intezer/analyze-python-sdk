import datetime
import time
from typing import Optional

from intezer_sdk import errors
from intezer_sdk._api import IntezerApi
from intezer_sdk.api import IntezerApiClient
from intezer_sdk.api import get_global_api
from intezer_sdk.consts import AnalysisStatusCode
from intezer_sdk.consts import CHECK_STATUS_INTERVAL


class Operation:
    """
    The Operation class is used to represent an asynchronous operation with the Intezer API.
    """

    def __init__(self, url: str, name: str, api: IntezerApiClient = None):
        """
        Initializes the Operation instance with the given url, name, and api (defaults to the global API instance if not specified).
        :param url: The URL of the operation that will be used to query the result.
        :param name: The name of the operation.
        :param api: The API connection to Intezer.
        """
        self.status = AnalysisStatusCode.IN_PROGRESS
        self.url = url
        self.result = None
        self.name = name
        self._api = IntezerApi(api or get_global_api())

    def get_result(self):
        """
        Returns the result of the operation, raising an error if the operation is still running.
        :return: The operation result
        """
        if self.status != AnalysisStatusCode.FINISHED:
            if not self.check_status():
                raise errors.OperationStillRunningError(self.name)
        return self.result

    def check_status(self) -> bool:
        """
       Check the status of the operation.
       :return: Returns a boolean indicating whether the operation has finished or is still running.
       """
        if self.result:
            return True

        operation_result = self._api.get_url_result(self.url)
        if operation_result['status'] == 'succeeded':
            self.result = operation_result['result']
            self.status = AnalysisStatusCode.FINISHED
            return True

        return False

    def wait_for_completion(self,
                            interval: int = None,
                            sleep_before_first_check=False,
                            wait_timeout: Optional[datetime.timedelta] = None) -> None:
        """
        Blocks until the operation is completed.
        :param interval: The interval to wait between checks in seconds.
        :param sleep_before_first_check: Whether to sleep before the first status check.
        :param wait_timeout: Maximum duration to wait for analysis completion in seconds.
        """
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
