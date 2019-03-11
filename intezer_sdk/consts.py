from enum import Enum

from intezer_sdk import SDK_VERSION


class AnalysisStatusCode(Enum):
    send = 201
    in_progress = 202
    finish = 200


USER_AGENT = 'intzersdk-python-%s' % SDK_VERSION
