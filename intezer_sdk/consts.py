from enum import Enum

from intezer_sdk import SDK_VERSION


class analysis_status_code(Enum):
    SENT = 1
    IN_PROGRESS = 2
    FINISH = 3


BASE_URL = 'https://analyze.intezer.com/api/'
API_VERSION = 'v2-0'
USER_AGENT = 'intzersdk-python-{}'.format(SDK_VERSION)
