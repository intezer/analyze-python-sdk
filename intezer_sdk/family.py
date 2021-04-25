import typing

from intezer_sdk import errors, consts
from intezer_sdk.api import IntezerApi
from intezer_sdk.api import get_global_api
from intezer_sdk.operation import PaginatedOperation


class Family:
    def __init__(self, family_id: str, name: str = None, family_type: str = None, *, api: IntezerApi = None):
        self.family_id = family_id
        self._name = name
        self._type = family_type
        self._api = api or get_global_api()
        self._get_files_operation = None

    def fetch_info(self):
        info = self._api.get_family_info(self.family_id)
        if not info:
            raise errors.FamilyWasNotFound(self.family_id)

        self._name = info['family_name']
        self._type = info['family_type']

    @property
    def name(self) -> str:
        if not self._name:
            self.fetch_info()

        return self._name

    @property
    def type(self) -> str:
        if not self._type:
            self.fetch_info()

        return self._type

    def find_family_related_files(self, wait: typing.Union[bool, int] = False):
        if not self._get_files_operation:
            result_url = self._api.get_family_related_files_by_family_id(self.family_id)
            self._get_files_operation = PaginatedOperation(result_url,
                                                           wait,
                                                           default_limit=consts.DEFAULT_FAMILY_FILES_LIMIT)

        return self._get_files_operation


def get_family_by_name(family_name: str, api: IntezerApi = None) -> typing.Optional[Family]:
    api = api or get_global_api()
    family_info = api.get_family_by_name(family_name)
    if family_info:
        return Family(family_info['family_id'], family_info['family_name'])

    return None
