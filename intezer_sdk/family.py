import typing

from intezer_sdk import errors
from intezer_sdk.api import IntezerApi
from intezer_sdk.api import get_global_api
from intezer_sdk.operation import PaginatedOperation


class Family(object):
    def __init__(self, api: IntezerApi = None):
        self.family_id = None
        self.family_name = None
        self.related_samples = None
        self._api = api or get_global_api()
        self._get_files_operation = None

    def init_by_family_name(self, family_name: str):
        if self.family_id:
            raise errors.FamilyHasAlreadyBeenInitialized()

        family_info = self._api.get_family_by_name(family_name)

        self._init_by_family_info(family_info)

    def init_by_family_id(self, family_id: str):
        if self.family_id:
            raise errors.FamilyHasAlreadyBeenInitialized()

        family_info = self._api.get_family_info(family_id)

        self._init_by_family_info(family_info)

    def _init_by_family_info(self, family_info: dict):
        if not family_info:
            raise errors.FamilyNotFound()

        self.family_id = family_info['family_id']
        self.family_name = family_info['family_name']

    def find_family_related_files(self, wait: typing.Union[bool, int] = False):
        if not self.family_id:
            raise errors.FamilyWasNotCreated()

        if not self._get_files_operation:
            result_url = self._api.get_family_related_files_by_family_id(self.family_id)
            self._get_files_operation = PaginatedOperation(result_url, wait)

        return self._get_files_operation


def get_family_by_name(family_name: str):
    family = Family()
    family.init_by_family_name(family_name)
    return family


def get_family_by_id(family_id: str):
    family = Family()
    family.init_by_family_id(family_id)
    return family
