from typing import Optional

import requests


def _parse_erroneous_response(response: requests.Response):
    try:
        data = response.json()
        return data.get('error', '')
    except ValueError:
        return ''


class IntezerError(Exception):
    pass


class UnsupportedOnPremiseVersionError(IntezerError):
    pass


UnsupportedOnPremiseVersion = UnsupportedOnPremiseVersionError


class ServerError(IntezerError):
    def __init__(self, message: str, response: requests.Response):
        self.response = response
        detailed_error = _parse_erroneous_response(response)
        if detailed_error:
            message = f'{message}. Error:{detailed_error}'
        super().__init__(message)


class AnalysisHasAlreadyBeenSentError(IntezerError):
    def __init__(self):
        super().__init__('Analysis already been sent')


AnalysisHasAlreadyBeenSent = AnalysisHasAlreadyBeenSentError


class IndexHasAlreadyBeenSentError(IntezerError):
    def __init__(self):
        super().__init__('Index already been sent')


IndexHasAlreadyBeenSent = IndexHasAlreadyBeenSentError


class FamilyNotFoundError(IntezerError):
    def __init__(self, family_id: str):
        super().__init__(f'Family not found: {family_id}')


class HashDoesNotExistError(ServerError):
    def __init__(self, response: requests.Response):
        super().__init__('Hash was not found', response)


class ReportDoesNotExistError(IntezerError):
    def __init__(self):
        super().__init__('Report was not found')


class AnalysisIsAlreadyRunningError(ServerError):
    def __init__(self, response: requests.Response, running_analysis_id: Optional[str]):
        super().__init__('Analysis already running', response)
        self.analysis_id = running_analysis_id


AnalysisIsAlreadyRunning = AnalysisIsAlreadyRunningError


class InsufficientQuotaError(ServerError):
    def __init__(self, response: requests.Response):
        super().__init__('Insufficient quota', response)


InsufficientQuota = InsufficientQuotaError


class GlobalApiIsNotInitializedError(IntezerError):
    def __init__(self):
        super().__init__('Global API is not initialized')


GlobalApiIsNotInitialized = GlobalApiIsNotInitializedError


class AnalysisIsStillRunningError(IntezerError):
    def __init__(self):
        super().__init__('Analysis is still running')


AnalysisIsStillRunning = AnalysisIsStillRunningError


class AnalysisFailedError(IntezerError):
    def __init__(self):
        super().__init__('Analysis failed')


class InvalidApiKeyError(ServerError):
    def __init__(self, response: requests.Response):
        super().__init__('Invalid api key', response)


InvalidApiKey = InvalidApiKeyError


class IndexFailedError(ServerError):
    def __init__(self, response: requests.Response):
        super().__init__('Index operation failed', response)


IndexFailed = IndexFailedError


class OperationStillRunningError(IntezerError):
    def __init__(self, operation):
        super().__init__(f'{operation} is still running')


SubAnalysisOperationStillRunning = OperationStillRunningError
SubAnalysisOperationStillRunningError = OperationStillRunningError


class SubAnalysisNotFoundError(IntezerError):
    def __init__(self, analysis_id: str):
        super().__init__(f'analysis {analysis_id} is not found')


class InsufficientPermissionsError(ServerError):
    def __init__(self, response: requests.Response):
        super().__init__('Account does not have permission to this route', response)


class InvalidAlertMappingError(IntezerError):
    def __init__(self, response: requests.Response):
        super().__init__('Bad request - the mapping is probably malformed', response)
