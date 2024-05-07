import gzip
import logging
from typing import List

import requests

from intezer_sdk.api import IntezerApiClient
from intezer_sdk.api import raise_for_status
from intezer_sdk.consts import SCAN_MAX_UPLOAD_RETRIES


class EndpointScanApi:
    def __init__(self, scan_id: str, api: IntezerApiClient, max_upload_retries: int = SCAN_MAX_UPLOAD_RETRIES):
        self.api = api
        if not scan_id:
            raise ValueError('scan_id must be provided')
        self.scan_id = scan_id
        self.base_url = f"{api.base_url.replace('/api/', '')}/scans/scans/{scan_id}"
        self.max_upload_retries = max_upload_retries

    def request_with_refresh_expired_access_token(self, *args, **kwargs):
        return self.api.request_with_refresh_expired_access_token(base_url=self.base_url, *args, **kwargs)

    def send_host_info(self, host_info: dict):
        response = self.request_with_refresh_expired_access_token(path='/host-info',
                                                                  data=host_info,
                                                                  method='POST')
        raise_for_status(response)

    def send_processes_info(self, processes_info: dict):
        response = self.request_with_refresh_expired_access_token(path='/processes-info',
                                                                  data=processes_info,
                                                                  method='POST')
        raise_for_status(response)

    def send_all_loaded_modules_info(self, all_loaded_modules_info: dict):
        response = self.request_with_refresh_expired_access_token(path=f'/processes/loaded-modules-info',
                                                                  data=all_loaded_modules_info,
                                                                  method='POST')
        raise_for_status(response)

    def send_loaded_modules_info(self, pid, loaded_modules_info: dict):
        response = self.request_with_refresh_expired_access_token(path=f'/processes/{pid}/loaded-modules-info',
                                                                  data=loaded_modules_info,
                                                                  method='POST')
        raise_for_status(response)

    def send_injected_modules_info(self, injected_module_list: dict):
        response = self.request_with_refresh_expired_access_token(path='/injected-modules-info',
                                                                  data=injected_module_list,
                                                                  method='POST')
        raise_for_status(response)

    def send_scheduled_tasks_info(self, scheduled_tasks_info: dict):
        response = self.request_with_refresh_expired_access_token(path='/scheduled-tasks-info',
                                                                  data=scheduled_tasks_info,
                                                                  method='POST')
        raise_for_status(response)

    def send_file_module_differences(self, file_module_differences: dict):
        response = self.request_with_refresh_expired_access_token(path='/file-module-differences',
                                                                  data=file_module_differences,
                                                                  method='POST')
        raise_for_status(response)

    def send_files_info(self, files_info: dict) -> List[str]:
        """
        :param files_info: endpoint scan files info
        :return: list of file hashes to upload
        """
        response = self.request_with_refresh_expired_access_token(path='/files-info',
                                                                  data=files_info,
                                                                  method='POST')
        raise_for_status(response)
        return response.json()['result']

    def send_memory_module_dump_info(self, memory_modules_info: dict) -> List[str]:
        """
        :param memory_modules_info: endpoint scan memory modules info
        :return: list of file hashes to upload
        """
        response = self.request_with_refresh_expired_access_token(path='/memory-module-dumps-info',
                                                                  data=memory_modules_info,
                                                                  method='POST')
        raise_for_status(response)
        return response.json()['result']

    def upload_collected_binary(self, file_path: str, collected_from: str):
        file_data = open(file_path, 'rb').read()
        compressed_data = gzip.compress(file_data, compresslevel=9)
        logger = logging.getLogger(__name__)
        # we have builtin retry for connection errors, but we want to retry on 500 errors as well
        for retry_count in range(self.max_upload_retries):
            try:
                response = self.request_with_refresh_expired_access_token(
                    path=f'/{collected_from}/collected-binaries',
                    data=compressed_data,
                    headers={'Content-Type': 'application/octet-stream', 'Content-Encoding': 'gzip'},
                    method='POST')
                raise_for_status(response)
                return
            except requests.HTTPError:
                if self.max_upload_retries - retry_count <= 1:
                    raise
                logger.warning(f'Failed to upload {file_path}, retrying')
            except Exception:
                raise

    def end_scan(self, scan_summary: dict):
        response = self.request_with_refresh_expired_access_token(path='/end',
                                                                  data=scan_summary,
                                                                  method='POST')
        raise_for_status(response)
