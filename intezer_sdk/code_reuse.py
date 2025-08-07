from time import sleep
from typing import Optional

from intezer_sdk import api
from intezer_sdk.api import IntezerApiClient
from intezer_sdk._api import IntezerApi


class Block:
    def __init__(self, address: int, software_type: str, families: list[str]):
        self.address = address
        self.software_type = software_type
        self.families = families
        self.is_common = software_type == "common"


class CodeReuse:
    """
    Get code reuse for a file.

    Parameters:
        api_client (Optional[IntezerApiClient]): An optional Intezer API client instance. If not provided, the global
        API client will be used.
    """

    def __init__(self, api_client: Optional[IntezerApiClient] = None):
        self._api = IntezerApi(api_client or api.get_global_api())

    def _get_result_from_task(self, result_url: str):
        response = self._api.api.request_with_refresh_expired_access_token(
            "GET", result_url)
        while response.status_code == 202:
            sleep(2)
            response = self._api.api.request_with_refresh_expired_access_token(
                "GET", result_url)
        response.raise_for_status()
        return response.json()['result']

    def get_code_blocks(self, sha256: str) -> list[Block]:
        """
        Retrieves a report containing information about reused code blocks for the given SHA-256 hash.

        Parameters:
            sha256_hash (str): The SHA-256 hash of the file to analyze.

        Returns:
            list[Block]: A sorted list of Block objects representing the code blocks found in the analysis.
        """
        result_url = self._api.get_code_reuse_by_code_block(sha256)
        # This endpoint acts different. We don't get a status and instead have to use
        # the HTTP status code to wait for the report.
        result = self._get_result_from_task(result_url)
        blocks: list[Block] = []
        for addr, val in result["blocks"].items():
            blocks.append(
                Block(int(addr), val["software_type"], val["code_reuse"]))
        return sorted(blocks, key=lambda b: b.address)
