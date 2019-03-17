import sys
from pprint import pprint

from intezer_sdk import api
from intezer_sdk import consts
from intezer_sdk.index import Index


def index_by_sha256_with_wait(sha256, index_as, family_name=None):  # type: (str, str, str) -> None
    api.set_global_api('<api_key>')

    index = Index(sha256=sha256, index_as=consts.IndexType.from_str(index_as), family_name=family_name)
    index.send(wait=True)
    pprint('Index operation:{}, Index ID:{}'.format(index.status.value, index.index_id))


def analysis_by_hash_without_wait(sha256, index_as, family_name=None):  # type: (str, str, str) -> None
    api.set_global_api('<api_key>')

    index = Index(sha256=sha256, index_as=consts.IndexType.from_str(index_as), family_name=family_name)
    index.send(wait=True)
    pprint('Index operation:{}, Index ID:{}'.format(index.status, index.index_id))


if __name__ == '__main__':
    index_by_sha256_with_wait(*sys.argv[1:])
