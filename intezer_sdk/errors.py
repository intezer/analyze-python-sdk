class IntezerError(Exception):
    pass


class AnalysisHasAlreadyBeenSent(IntezerError):
    def __init__(self):
        super(AnalysisHasAlreadyBeenSent, self).__init__('Analysis already been sent')


class IndexHasAlreadyBeenSent(IntezerError):
    def __init__(self):
        super(IndexHasAlreadyBeenSent, self).__init__('Index already been sent')


class AnalysisDoesNotExistError(IntezerError):
    def __init__(self):
        super(AnalysisDoesNotExistError, self).__init__('Analysis was not found')


class HashDoesNotExistError(IntezerError):
    def __init__(self):
        super(HashDoesNotExistError, self).__init__('Hash was not found')


class ReportDoesNotExistError(IntezerError):
    def __init__(self):
        super(ReportDoesNotExistError, self).__init__('Report was not found')


class AnalysisIsAlreadyRunning(IntezerError):
    def __init__(self):
        super(AnalysisIsAlreadyRunning, self).__init__('Analysis already running')


class InsufficientQuota(IntezerError):
    def __init__(self):
        super(InsufficientQuota, self).__init__('Insufficient quota')


class GlobalApiIsNotInitialized(IntezerError):
    def __init__(self):
        super(GlobalApiIsNotInitialized, self).__init__('Global API is not initialized')


class AnalysisIsStillRunning(IntezerError):
    def __init__(self):
        super(AnalysisIsStillRunning, self).__init__('Analysis is still running')


class InvalidApiKey(IntezerError):
    def __init__(self):
        super(InvalidApiKey, self).__init__('Invalid api key')
