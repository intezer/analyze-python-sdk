from enum import Enum

from intezer_sdk import __version__


class AnalysisStatusCode(Enum):
    CREATED = 'created'
    IN_PROGRESS = 'in_progress'
    FINISH = 'finished'


class IndexStatusCode(Enum):
    CREATED = 'created'
    IN_PROGRESS = 'in_progress'
    FINISH = 'finished'


class IndexType(Enum):
    TRUSTED = 'trusted'
    MALICIOUS = 'malicious'


BASE_URL = 'https://analyze.intezer.com/api/'
API_VERSION = 'v2-0'
USER_AGENT = 'intezer-python-sdk-{}'.format(__version__)
CHECK_STATUS_INTERVAL = 1
