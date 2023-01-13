import enum
import glob
import json
import os
from typing import List

from intezer_sdk import consts
from intezer_sdk.analysis import logger
from intezer_sdk.api import EndpointScanApi
from intezer_sdk.api import IntezerApi
from intezer_sdk.api import get_global_api
from intezer_sdk.base_analysis import BaseAnalysis
from intezer_sdk.sub_analysis import SubAnalysis
from pathlib import Path


class EndpointAnalysis(BaseAnalysis):
    class EndpointAnalysisEndReason(enum.Enum):
        DONE = 'done'
        INTERRUPTED = 'interrupted'
        FAILED = 'failed'

    def __init__(self,
                 api: IntezerApi = None,
                 scan_api: EndpointScanApi = None,
                 metadata_dir: Path = None,
                 files_dir: Path = None,
                 fileless_dir: Path = None,
                 memory_modules_dir: Path = None):
        super().__init__(api)
        self._scan_api = scan_api
        if metadata_dir:
            self._metadata_dir = metadata_dir
            self._files_dir = files_dir or os.path.join(self._metadata_dir, '../files')
            self._fileless_dir = fileless_dir or os.path.join(self._metadata_dir, '../fileless')
            self._memory_modules_dir = memory_modules_dir or os.path.join(self._metadata_dir, '../memory_modules')
        self._sub_analyses: List[SubAnalysis] = []
        self.scan_id = None

    @classmethod
    def from_analysis_id(cls, analysis_id: str, api: IntezerApi = None):
        api = api or get_global_api()
        response = api.get_endpoint_analysis_response(analysis_id, True)
        return cls._create_analysis_from_response(response, api, analysis_id)

    def _query_status_from_api(self):
        return self._api.get_endpoint_analysis_response(self.analysis_id, False)

    def get_sub_analyses(self, verdicts: List[str] = None) -> List[SubAnalysis]:
        self._assert_analysis_finished()
        if not self._sub_analyses:
            self._init_sub_analyses()

        if verdicts:
            return [sub_analysis for sub_analysis in self._sub_analyses if sub_analysis.verdict in verdicts]
        else:
            return self._sub_analyses

    def _init_sub_analyses(self):
        all_sub_analysis = self._api.get_endpoint_sub_analyses(self.analysis_id, [])
        for sub_analysis in all_sub_analysis:
            sub_analysis_object = SubAnalysis(sub_analysis['sub_analysis_id'],
                                              self.analysis_id,
                                              sub_analysis['sha256'],
                                              sub_analysis['source'],
                                              sub_analysis.get('extraction_info'),
                                              api=self._api,
                                              verdict=sub_analysis['verdict'])
            self._sub_analyses.append(sub_analysis_object)

    def _send_analyze_to_api(self, **additional_parameters) -> str:
        try:
            if not self._metadata_dir:
                raise ValueError('Scan directory is not set')
            if not os.path.exists(self._metadata_dir):
                raise ValueError('Scan directory does not exist')
            if not os.path.exists(self._files_dir):
                raise ValueError('Files directory does not exist')
            if not os.path.exists(self._fileless_dir):
                raise ValueError('Fileless directory does not exist')
            if not os.path.exists(self._memory_modules_dir):
                raise ValueError('Memory modules directory does not exist')

            with open(os.path.join(self._metadata_dir, 'scanner_info.json')) as f:
                scanner_info = json.load(f)

            result = self._api.create_endpoint_analysis(scanner_info)
            self.scan_id = result['scan_id']
            self.analysis_id = result['analysis_id']
            self.status = consts.AnalysisStatusCode.IN_PROGRESS

            if not self._scan_api:
                self._scan_api = EndpointScanApi(api_key=self._api.api_key,
                                                 base_url=self._api.base_url,
                                                 scan_id=self.scan_id,
                                                 verify_ssl=self._api.verify_ssl,
                                                 user_agent=self._api.user_agent)

            with open(os.path.join(self._metadata_dir, 'host_info.json')) as f:
                host_info = json.load(f)
            self._scan_api.send_host_info(host_info)

            with open(os.path.join(self._metadata_dir, 'scheduled_tasks_info.json')) as f:
                scheduled_tasks_info = json.load(f)
            self._scan_api.send_scheduled_tasks_info(scheduled_tasks_info)

            with open(os.path.join(self._metadata_dir, 'processes_info.json')) as f:
                processes_info = json.load(f)
            self._scan_api.send_processes_info(processes_info)

            with open(os.path.join(self._metadata_dir, 'injected_modules_info.json')) as f:
                injected_modules_info = json.load(f)
            self._scan_api.send_injected_modules_info(injected_modules_info)

            with open(os.path.join(self._metadata_dir, 'file_module_differences.json')) as f:
                file_module_differences = json.load(f)
            self._scan_api.send_file_module_differences(file_module_differences)

            for loaded_module_info_file in glob.glob(os.path.join(self._metadata_dir, '*_loaded_modules_info.json')):
                with open(loaded_module_info_file, 'r') as f:
                    loaded_modules_info = json.load(f)
                pid = loaded_module_info_file.split('_')[0]
                self._scan_api.send_loaded_modules_info(pid, loaded_modules_info)

            for files_info_file in glob.glob(os.path.join(self._metadata_dir, 'files_info_*.json')):
                with open(files_info_file, 'r') as f:
                    files_info = json.load(f)

                files_to_upload = self._scan_api.send_files_info(files_info)

                for file_to_upload in files_to_upload:
                    file_path = os.path.join(self._files_dir, file_to_upload)
                    if os.path.exists(file_path):
                        self._scan_api.upload_collected_binary(file_path, 'file-system')
                    else:
                        logger.warning('File %s does not exist', file_path)

            for memory_module_dump_info_file in glob.glob(os.path.join(self._metadata_dir,
                                                                       'memory_module_dump_info_*.json')):
                with open(memory_module_dump_info_file, 'r') as f:
                    memory_module_dump_info = json.load(f)

                memory_modules_to_upload = self._scan_api.send_memory_module_dump_info(memory_module_dump_info)

                for memory_module_to_upload in memory_modules_to_upload:
                    memory_module_path = os.path.join(self._memory_modules_dir, memory_module_to_upload)
                    fileless_module_path = os.path.join(self._memory_modules_dir, memory_module_to_upload)
                    if os.path.exists(memory_module_path):
                        self._scan_api.upload_collected_binary(memory_module_path, 'memory')
                    elif os.path.exists(fileless_module_path):
                        self._scan_api.upload_collected_binary(fileless_module_path, 'fileless')
                    else:
                        logger.warning('Memory module %s does not exist', memory_module_path)
        except KeyboardInterrupt:
            if self.status == consts.AnalysisStatusCode.IN_PROGRESS:
                self._scan_api.close_scan_store(scan_summary={'reason': self.EndpointAnalysisEndReason.INTERRUPTED})
            self.status = consts.AnalysisStatusCode.FAILED
        finally:
            if self.status == consts.AnalysisStatusCode.IN_PROGRESS:
                self._scan_api.close_scan_store(scan_summary={'reason': self.EndpointAnalysisEndReason.FAILED})
            self.status = consts.AnalysisStatusCode.FAILED
        return self.analysis_id


