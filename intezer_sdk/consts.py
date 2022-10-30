from enum import Enum
from enum import IntEnum

from intezer_sdk import __version__


class AnalysisStatusCode(Enum):
    CREATED = 'created'
    IN_PROGRESS = 'in_progress'
    QUEUED = 'queued'
    FAILED = 'failed'
    FINISH = 'finished'
    FINISHED = 'finished'


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


class OnPremiseVersion(IntEnum):
    V21_11 = 21.11


ANALYZE_URL = 'https://analyze.intezer.com'
BASE_URL = '{}/api/'.format(ANALYZE_URL)
API_VERSION = 'v2-0'
USER_AGENT = 'intezer-python-sdk-{}'.format(__version__)
CHECK_STATUS_INTERVAL = 1
