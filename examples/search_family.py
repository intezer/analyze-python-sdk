import sys

from intezer_sdk import api
from intezer_sdk import family as intezer_family


def search_family(family_name: str):
    api.set_global_api('<api_key>')
    family = intezer_family.search_family(family_name)
    print(family.name)
    print(family.type)


if __name__ == '__main__':
    search_family(*sys.argv[1:])
