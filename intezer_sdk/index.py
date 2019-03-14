import time

from intezer_sdk import consts
from intezer_sdk import errors
from intezer_sdk.api import IntezerApi
from intezer_sdk.api import get_global_api

try:
    from http import HTTPStatus
except ImportError:
    import httplib as HTTPStatus


class Index(object):
    def __init__(self,
                 file_path=None,
                 sha256=None,
                 api=None,
                 index_as=None,
                 family_name=None):  # type: (str, str, IntezerApi, IndexType, str) -> None
        if (sha256 is not None) == (file_path is not None):
            raise ValueError('Choose between sha256 or file indexing')

        if (index_as == consts.IndexType.MALICIOUS) and (family_name is None):
            raise ValueError('family_name is mandatory if the index type is malicious')

        self.status = None  # type: IndexStatusCode
        self.index_id = None  # type: str
        self._sha256 = sha256  # type: str
        self._file_path = file_path  # type: str
        self._api = api or get_global_api()  # type: IntezerApi
        self._index_as = index_as  # type: IndexType
        self._family_name = family_name  # type: str

    def send(self, wait=False):  # type: (bool) -> None
        if self.index_id:
            raise errors.IndexHasAlreadyBeenSent()

        if self._sha256:
            self.index_id = self._api.index_by_sha256(self._sha256, self._index_as, self._family_name)
        else:
            self.index_id = self._api.index_by_file(self._file_path, self._index_as, self._family_name)

        self.status = consts.IndexStatusCode.CREATED

        if wait:
            self.wait_for_completion()

    def wait_for_completion(self):
        if self._is_index_operation_running():
            status_code = self.check_status()

            while status_code != consts.IndexStatusCode.FINISH:
                time.sleep(consts.CHECK_STATUS_INTERVAL)
                status_code = self.check_status()

    def check_status(self):
        if not self._is_index_operation_running():
            raise errors.IntezerError('Index operation isn\'t currently running')

        response = self._api.get_index_response(self.index_id)
        if response.status_code == HTTPStatus.OK:
            self.status = consts.IndexStatusCode.FINISH
        elif response.status_code == HTTPStatus.ACCEPTED:
            self.status = consts.IndexStatusCode.IN_PROGRESS
        else:
            raise errors.IntezerError('Error in response status code:{}'.format(response.status_code))

        return self.status

    def _is_index_operation_running(self):
        return self.status in (consts.IndexStatusCode.CREATED, consts.IndexStatusCode.IN_PROGRESS)
