from enum import Enum

from intezer_sdk import __version__


class AnalysisStatusCode(Enum):
    CREATED = 'created'
    IN_PROGRESS = 'in_progress'
    FINISH = 'finished'


BASE_URL = 'https://analyze.intezer.com/api/'
API_VERSION = 'v2-0'
USER_AGENT = 'intezer-python-sdk-{}'.format(__version__)
