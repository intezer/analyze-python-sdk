import enum

from intezer_sdk import __version__


class AutoName(enum.Enum):
    def _generate_next_value_(name, start, count, last_values):
        return name.lower()


class AnalysisStatusCode(enum.Enum):
    CREATED = 'created'
    IN_PROGRESS = 'in_progress'
    QUEUED = 'queued'
    FAILED = 'failed'
    FINISH = 'finished'
    FINISHED = 'finished'


class SoftwareType(AutoName):
    ADMINISTRATION_TOOL = enum.auto()
    APPLICATION = enum.auto()
    INSTALLER = enum.auto()
    LIBRARY = enum.auto()
    PACKER = enum.auto()
    MALWARE = enum.auto()
    INTERPRETER = enum.auto()
    MALICIOUS_PACKER = enum.auto()


class FileAnalysisVerdict(AutoName):
    TRUSTED = enum.auto()
    MALICIOUS = enum.auto()
    SUSPICIOUS = enum.auto()
    NEUTRAL = enum.auto()
    UNKNOWN = enum.auto()
    NOT_SUPPORTED = enum.auto()
    NO_THREATS = enum.auto()


class EndpointAnalysisVerdict(AutoName):
    NO_THREATS = enum.auto()
    MALICIOUS = enum.auto()
    SUSPICIOUS = enum.auto()
    INCOMPLETE = enum.auto()


class URLAnalysisVerdict(AutoName):
    NO_THREATS = enum.auto()
    SUSPICIOUS = enum.auto()
    MALICIOUS = enum.auto()


class IndexStatusCode(enum.Enum):
    CREATED = 'created'
    IN_PROGRESS = 'in_progress'
    FINISH = 'finished'
    FINISHED = 'finished'


class IndexType(AutoName):
    TRUSTED = enum.auto()
    MALICIOUS = enum.auto()

    @staticmethod
    def from_str(label):
        if label in ('TRUSTED', 'trusted'):
            return IndexType.TRUSTED
        elif label in ('MALICIOUS', 'malicious'):
            return IndexType.MALICIOUS
        else:
            raise NotImplementedError


class CodeItemType(AutoName):
    FILE = enum.auto()
    MEMORY_MODULE = enum.auto()


class OnPremiseVersion(enum.IntEnum):
    V21_11 = 21.11
    V22_10 = 22.10


ANALYZE_URL = 'https://analyze.intezer.com'
BASE_URL = '{}/api/'.format(ANALYZE_URL)
API_VERSION = 'v2-0'
USER_AGENT = 'intezer-python-sdk-{}'.format(__version__)
CHECK_STATUS_INTERVAL = 1
