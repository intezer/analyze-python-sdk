import datetime
from typing import Dict
from typing import Optional
from typing import Union

from intezer_sdk._api import IntezerApi
from intezer_sdk.operation import Operation


def handle_operation(operations: Dict[str, Operation],
                     api: IntezerApi,
                     operation: str,
                     result_url: str,
                     wait: Union[bool, int],
                     wait_timeout: Optional[datetime.timedelta]) -> Operation:
    if operation not in operations:
        operations[operation] = Operation(result_url, operation, api=api.api)

        if wait:
            if isinstance(wait, bool):
                operations[operation].wait_for_completion(sleep_before_first_check=True,
                                                          wait_timeout=wait_timeout)
            else:
                operations[operation].wait_for_completion(wait,
                                                          sleep_before_first_check=True,
                                                          wait_timeout=wait_timeout)

    return operations[operation]