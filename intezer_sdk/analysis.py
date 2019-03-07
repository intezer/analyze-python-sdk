try:
    from http import HTTPStatus
except ImportError:
    import httplib as HTTPStatus

import time

from intezer_sdk.api import IntezerApi
from intezer_sdk.exceptions import AnalysisDoesNotExistError
from intezer_sdk.exceptions import HashDoesNotExistError
from intezer_sdk.globals import ANALYSIS_STATUS_CODE


class Analysis(object):
    def __init__(self, file_path=None, file_hash=None, dynamic_unpacking=False, api=None):
        if (file_hash is not None) == (file_path is not None):
            raise ValueError('Choose between file or sha256 analysis')

        self.hash = file_hash  # type: str
        self.dynamic_unpacking = dynamic_unpacking  # type: bool
        self.file_path = file_path  # type: str
        self.analyses_id = None  # type: str
        self.report = None  # type: dict
        self.api = api or IntezerApi()

    def send(self, wait=False):
        params = {}

        if self.hash is not None:
            params['hash'] = self.hash
            response = self.api.request(path='/analyze-by-hash', params=params, method='POST')
            if response.status_code == HTTPStatus.NOT_FOUND:
                raise HashDoesNotExistError()
        else:
            if self.dynamic_unpacking:
                params['dynamic_unpacking'] = 'Auto'
            with open(self.file_path, 'rb') as file_to_upload:
                files = {'file': ('file_name', file_to_upload)}
                response = self.api.request(path='/analyze', files=files, params=params, method='POST')

        assert response.status_code == HTTPStatus.CREATED

        self.analyses_id = response.json()['result_url'].split('/')[2]

        if wait:
            self.wait_for_completion()
            return ANALYSIS_STATUS_CODE['succeeded']
        else:
            return ANALYSIS_STATUS_CODE['created']

    def wait_for_completion(self):
        status_code = self.check_status()

        while status_code != ANALYSIS_STATUS_CODE['succeeded']:
            time.sleep(1)
            status_code = self.check_status()

    def check_status(self):
        response = self._analyze_request()
        if response.status_code == HTTPStatus.OK:
            self.report = response.json()['result']

        return response.status_code

    def result(self):
        return self.report

    def _analyze_request(self):
        if self.analyses_id is None:
            raise AnalysisDoesNotExistError()

        response = self.api.request(path='/analyses/%s' % self.analyses_id, method='GET')
        response.raise_for_status()

        return response
