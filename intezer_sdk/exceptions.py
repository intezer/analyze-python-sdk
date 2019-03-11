class IntezerError(Exception):
    pass


class AnalysisAlreadyBeenSent(IntezerError):
    def __init__(self):
        super(AnalysisAlreadyBeenSent, self).__init__('Analysis already been sent')


class AnalysisDoesNotExistError(IntezerError):
    def __init__(self):
        super(AnalysisDoesNotExistError, self).__init__('Analysis was not found')


class HashDoesNotExistError(IntezerError):
    def __init__(self):
        super(HashDoesNotExistError, self).__init__('Hash was not found')


class ReportDoesNotExistError(IntezerError):
    def __init__(self):
        super(ReportDoesNotExistError, self).__init__('Report was not found')


class AnalysisAlreadyRunning(IntezerError):
    def __init__(self):
        super(AnalysisAlreadyRunning, self).__init__('Analysis already running')
