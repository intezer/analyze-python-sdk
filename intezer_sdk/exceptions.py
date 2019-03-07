from intezer_sdk.globals import ANALYSIS_STATUS_CODE


class IntezerError(Exception):
    pass


class AnalysisDoesNotExistError(IntezerError):
    def __init__(self):
        super().__init__('Analysis was not found', ANALYSIS_STATUS_CODE['analysis-was-not-found'])


class HashDoesNotExistError(IntezerError):
    def __init__(self):
        super().__init__('Hash was not found', ANALYSIS_STATUS_CODE['hash-was-not-found'])
