from dataclasses import dataclass
from http import HTTPStatus
from time import sleep
from typing import Optional
from typing import List

from intezer_sdk import api
from intezer_sdk.api import IntezerApiClient
from intezer_sdk._api import IntezerApi

@dataclass
class Block:
    address: int
    software_type: str
    families: List[str]

    @property
    def is_common(self):
        return self.software_type == 'common'


class CodeReuse:
    '''
    Get code reuse for a file.

    Parameters:
        api_client (Optional[IntezerApiClient]): An optional Intezer API client instance. If not provided, the global
        API client will be used.
    '''

    def __init__(self, api_client: Optional[IntezerApiClient] = None):
        self._api = IntezerApi(api_client or api.get_global_api())

    def _get_result_from_task(self, result_url: str):
        response = self._api.api.request_with_refresh_expired_access_token(
            'GET', result_url)
        while response.status_code == HTTPStatus.ACCEPTED:
            sleep(2)
            response = self._api.api.request_with_refresh_expired_access_token(
                'GET', result_url)
        response.raise_for_status()
        return response.json()['result']

    def get_code_blocks(self, sha256: str) -> List[Block]:
        '''
        Retrieves a report containing information about reused code blocks for the given SHA-256 hash.

        Parameters:
            sha256_hash (str): The SHA-256 hash of the file to analyze.

        Returns:
            List[Block]: A sorted list of Block objects representing the code blocks found in the analysis.
        '''
        result_url = self._api.get_code_reuse_by_code_block(sha256)
        # This endpoint acts different. We don't get a status and instead have to use
        # the HTTP status code to wait for the report.
        result = self._get_result_from_task(result_url)
        blocks: list[Block] = []
        for address, block in result['blocks'].items():
            blocks.append(
                Block(int(address), block['software_type'], block['code_reuse']))
        return sorted(blocks, key=lambda b: b.address)
