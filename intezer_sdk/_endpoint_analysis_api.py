import gzip
from typing import List
from urllib.parse import urlparse

from intezer_sdk.api import raise_for_status

from intezer_sdk.api import IntezerProxy


class EndpointScanApi:
    def __init__(self,
                 scan_id: str,
                 base_api: IntezerProxy):
        self.base_api = base_api
        if not scan_id:
            raise ValueError('scan_id must be provided')
        self.scan_id = scan_id
        api_base = f'https://{urlparse(base_api.base_url).netloc}'
        self.base_url = f'{api_base}/scans/scans/{scan_id}'

    def request_with_refresh_expired_access_token(self, *args, **kwargs):
        return self.base_api.request_with_refresh_expired_access_token(base_url=self.base_url, *args, **kwargs)

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
        with open(file_path, 'rb') as file_to_upload:
            file_data = file_to_upload.read()
            compressed_data = gzip.compress(file_data, compresslevel=9)
            response = self.request_with_refresh_expired_access_token(
                path=f'/{collected_from}/collected-binaries',
                data=compressed_data,
                headers={'Content-Type': 'application/octet-stream', 'Content-Encoding': 'gzip'},
                method='POST')

        raise_for_status(response)

    def close_scan(self, scan_summary: dict):
        response = self.request_with_refresh_expired_access_token(path='/end',
                                                                  data=scan_summary,
                                                                  method='POST')
        raise_for_status(response)
