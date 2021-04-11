import typing

from intezer_sdk import errors
from intezer_sdk.api import IntezerApi
from intezer_sdk.api import get_global_api


class Family:
    def __init__(self, family_id: str, name: str = None, family_type: str = None, *, api: IntezerApi = None):
        self.family_id = family_id
        self._name = name
        self._type = family_type
        self._api = api or get_global_api()

    def fetch_info(self):
        info = self._api.get_family_info(self.family_id)
        if not info:
            raise errors.FamilyNotFoundError(self.family_id)

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


def get_family_by_name(family_name: str, api: IntezerApi = None) -> typing.Optional[Family]:
    api = api or get_global_api()
    family = api.get_family_by_name(family_name)
    if family:
        return Family(family['family_id'], family['family_name'])

    return None
