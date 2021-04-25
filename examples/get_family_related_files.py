import sys

from intezer_sdk import api
from intezer_sdk.family import get_family_by_name


def get_family_related_files(family_name: str):
    api.set_global_api('<api_key>')
    family = get_family_by_name(family_name)
    related_files_operation = family.find_family_related_files(wait=True)

    result = related_files_operation.fetch_next(10)
    print(result)

    result = related_files_operation.fetch_next(5)
    print(result)


if __name__ == '__main__':
    get_family_related_files(*sys.argv[1:])
