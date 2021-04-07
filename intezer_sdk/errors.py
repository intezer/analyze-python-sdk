import requests


def _parse_erroneous_response(response: requests.Response):
    try:
        data = response.json()
        return data.get('error', '')
    except ValueError:
        return ''


class IntezerError(Exception):
    pass


class ServerError(IntezerError):
    def __init__(self, message: str, response: requests.Response):
        self.response = response
        detailed_error = _parse_erroneous_response(response)
        if detailed_error:
            message = '{}. Error:{}'.format(message, detailed_error)
        super().__init__(message)


class AnalysisHasAlreadyBeenSent(IntezerError):
    def __init__(self):
        super(AnalysisHasAlreadyBeenSent, self).__init__('Analysis already been sent')


class IndexHasAlreadyBeenSent(IntezerError):
    def __init__(self):
        super().__init__('Index already been sent')


class FamilyNotFoundError(IntezerError):
    def __init__(self, family_id: str):
        super().__init__('Family not found: {}'.format(family_id))


class HashDoesNotExistError(ServerError):
    def __init__(self, response: requests.Response):
        super().__init__('Hash was not found', response)


class ReportDoesNotExistError(IntezerError):
    def __init__(self):
        super().__init__('Report was not found')


class AnalysisIsAlreadyRunning(ServerError):
    def __init__(self, response: requests.Response):
        super().__init__('Analysis already running', response)


class InsufficientQuota(ServerError):
    def __init__(self, response: requests.Response):
        super().__init__('Insufficient quota', response)


class GlobalApiIsNotInitialized(IntezerError):
    def __init__(self):
        super().__init__('Global API is not initialized')


class AnalysisIsStillRunning(IntezerError):
    def __init__(self):
        super().__init__('Analysis is still running')


class InvalidApiKey(ServerError):
    def __init__(self, response: requests.Response):
        super().__init__('Invalid api key', response)


class IndexFailed(ServerError):
    def __init__(self, response: requests.Response):
        super().__init__('Index operation failed', response)


class SubAnalysisOperationStillRunning(IntezerError):
    def __init__(self, operation):
        super(SubAnalysisOperationStillRunning, self).__init__('{} is still running'.format(operation))
