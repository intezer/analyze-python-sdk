import typing

from typing import Optional
from typing import List

from intezer_sdk import errors
from intezer_sdk._api import IntezerApi
from intezer_sdk.api import IntezerApiClient
from intezer_sdk.api import get_global_api


class Family:
    def __init__(self,
                 family_id: str,
                 name: str = None,
                 family_type: str = None,
                 family_tags: Optional[List[str]] = None,
                 *,
                 api: IntezerApiClient = None):
        self.family_id = family_id
        self._name = name
        self._type = family_type
        self._tags = family_tags
        self._api = IntezerApi(api or get_global_api())

    def __eq__(self, other):
        return self is other or isinstance(other, Family) and self.family_id and other.family_id == self.family_id

    @classmethod
    def from_family_id(cls, family_id: str, api: IntezerApiClient = None) -> typing.Optional['Family']:
        try:
            family = cls(family_id, api=api)
            family.fetch_info()
            return family
        except errors.FamilyNotFoundError:
            return None

    def fetch_info(self):
        info = self._api.get_family_info(self.family_id)
        if not info:
            raise errors.FamilyNotFoundError(self.family_id)

        self._name = info['family_name']
        self._type = info['family_type']

        family_tags = info.get('family_tags')
        if family_tags:
            self._tags = family_tags

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

    @property
    def tags(self) -> Optional[List[str]]:
        if not self._tags:
            self.fetch_info()

        return self._tags


def get_family_by_name(family_name: str, api: IntezerApiClient = None) -> typing.Optional[Family]:
    family = IntezerApi(api or get_global_api()).get_family_by_name(family_name)
    if family:
        return Family(family['family_id'], family['family_name'])

    return None
