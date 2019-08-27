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

    @staticmethod
    def from_str(label):
        if label in ('TRUSTED', 'trusted'):
            return IndexType.TRUSTED
        elif label in ('MALICIOUS', 'malicious'):
            return IndexType.MALICIOUS
        else:
            raise NotImplementedError


class CodeItemType(Enum):
    FILE = 'file'
    MEMORY_MODULE = 'memory_module'


BASE_URL = 'https://analyze.intezer.com/api/'
API_VERSION = 'v2-0'
USER_AGENT = 'intezer-python-sdk-{}'.format(__version__)
CHECK_STATUS_INTERVAL = 1
