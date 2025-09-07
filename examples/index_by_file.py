import sys
from pprint import pprint
from typing import Optional

from intezer_sdk import api
from intezer_sdk import consts
from intezer_sdk.file import File


def index_by_file_with_wait(file_path: str, index_as: str, family_name: Optional[str] = None) -> None:
    api.set_global_api('<api_key>')

    file_obj = File(file_path=file_path)
    file_obj.index(consts.IndexType.from_str(index_as), family_name=family_name, wait=True)
    pprint(f'Index operation: {file_obj.index_status.value}, Index ID: {file_obj.index_id}')


def index_by_file_without_wait(file_path: str, index_as: str, family_name: Optional[str] = None) -> None:
    api.set_global_api('<api_key>')

    file_obj = File(file_path=file_path)
    file_obj.index(consts.IndexType.from_str(index_as), family_name=family_name)
    file_obj.wait_for_index_completion()
    pprint(f'Index operation: {file_obj.index_status.value}, Index ID: {file_obj.index_id}')


if __name__ == '__main__':
    index_by_file_with_wait(*sys.argv[1:])
