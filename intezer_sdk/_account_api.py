from http import HTTPStatus
from typing import List
from typing import Optional

from intezer_sdk import errors
from intezer_sdk.api import IntezerApiClient
from intezer_sdk.api import get_global_api
from intezer_sdk.api import raise_for_status


class AccountApi:
    def __init__(self, api: Optional[IntezerApiClient]):
        self.api = api or get_global_api()

    def get_my_quota(self, raise_on_no_file_quota=False, raise_on_no_endpoint_quota=False) -> dict:
        response = self.api.request_with_refresh_expired_access_token('GET', '/current-quota-usage')
        raise_for_status(response)
        result = response.json()['result']
        if raise_on_no_file_quota and result['file_scans']['quota'] - result['file_scans']['usage'] <= 0:
            raise errors.InsufficientQuotaError(response)
        if raise_on_no_endpoint_quota and result['endpoint_scans']['quota'] - result['endpoint_scans']['usage'] <= 0:
            raise errors.InsufficientQuotaError(response)
        return result

    def get_my_account(self) -> dict:
        response = self.api.request_with_refresh_expired_access_token('GET', '/accounts/me')
        raise_for_status(response)
        return response.json()['result']

    def get_account(self, account_id: str) -> Optional[dict]:
        response = self.api.request_with_refresh_expired_access_token('GET', f'/accounts/{account_id}')
        if response.status_code == HTTPStatus.NOT_FOUND:
            return None

        raise_for_status(response)
        return response.json()['result']

    def get_organization_accounts(self) -> List[dict]:
        response = self.api.request_with_refresh_expired_access_token('GET', f'/accounts')
        raise_for_status(response)
        return response.json()['result']
