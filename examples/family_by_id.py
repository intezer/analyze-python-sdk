import sys
from pprint import pprint

from intezer_sdk import api
from intezer_sdk.family import Family


def fetch_family_by_family_id(family_id: str):
    api.set_global_api('<api_key>')
    family = Family.from_family_id(family_id=family_id)
    family.fetch_info()

    pprint(family.name)
    pprint(family.type)
    pprint(family.tags)


if __name__ == '__main__':
    fetch_family_by_family_id(*sys.argv[1:])
