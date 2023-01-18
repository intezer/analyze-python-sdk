import glob
import json
import os
import pathlib
from typing import List

from intezer_sdk import consts
from intezer_sdk._endpoint_analysis_api import EndpointScanApi
from intezer_sdk.analysis import logger
from intezer_sdk.api import IntezerApi
from intezer_sdk.api import get_global_api
from intezer_sdk.base_analysis import Analysis
from intezer_sdk.consts import EndpointAnalysisEndReason
from intezer_sdk.sub_analysis import SubAnalysis


class EndpointAnalysisEndReason(enum.Enum):
    DONE = 'done'
    INTERRUPTED = 'interrupted'
    FAILED = 'failed'

class EndpointAnalysis(BaseAnalysis):
    """
    EndpointAnalysis is a class for analyzing endpoints. It is a subclass of the Analysis class and requires an API connection to Intezer.
    """
    def __init__(self,
                 api: IntezerApi = None,
                 scan_api: EndpointScanApi = None,
                 metadata_dir: str = None,
                 files_dir: str = None,
                 fileless_dir: str = None,
                 memory_modules_dir: str = None):
        """
        Initializes an EndpointAnalysis object.

        :param api: The API connection to Intezer.
        """
        super().__init__(api)
        self._scan_api = scan_api
        if metadata_dir:
            files_dir = files_dir or os.path.join(metadata_dir, '../files')
            fileless_dir = fileless_dir or os.path.join(metadata_dir, '../fileless')
            memory_modules_dir = memory_modules_dir or os.path.join(metadata_dir, '../memory_modules')
            self._metadata_dir = pathlib.Path(metadata_dir)
            self._files_dir = pathlib.Path(files_dir)
            self._fileless_dir = pathlib.Path(fileless_dir)
            self._memory_modules_dir = pathlib.Path(memory_modules_dir)

        self._sub_analyses: List[SubAnalysis] = []
        self.scan_id = None

    @classmethod
    def from_analysis_id(cls, analysis_id: str, api: IntezerApi = None):
        """
        Returns an EndpointAnalysis instance with the given analysis ID.
        Returns None when analysis doesn't exist.

        :param analysis_id: The ID of the analysis to retrieve.
        :param api: The API connection to Intezer.
        :return: An EndpointAnalysis instance with the given analysis ID.
        """
        api = api or get_global_api()
        response = api.get_endpoint_analysis_response(analysis_id, True)
        return cls._create_analysis_from_response(response, api, analysis_id)

    def _query_status_from_api(self):
        return self._api.get_endpoint_analysis_response(self.analysis_id, False)

    def get_sub_analyses(self, verdicts: List[str] = None) -> List[SubAnalysis]:
        """
        Get the sub_analyses of the current analysis.
        :param verdicts: A list of the verdicts to filter by.
        :return: A list of SubAnalysis objects.
        """
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

            self._create_scan()

            if not self.scan_id:
                raise ValueError('Failed to create scan')

            self.status = consts.AnalysisStatusCode.IN_PROGRESS
            self._initialize_endpoint_api()

            self._send_host_info()
            self._send_scheduled_tasks_info()
            self._send_processes_info()
            self._send_loaded_modules_info()
            self._send_files_info_and_upload_required()
            self._send_module_differences()
            self._send_injected_modules_info()
            self._send_memory_module_dump_info_and_upload_required()

        except KeyboardInterrupt:
            if self.status == consts.AnalysisStatusCode.IN_PROGRESS:
                self._scan_api.close_scan_store(scan_summary={'reason': EndpointAnalysisEndReason.INTERRUPTED.value})
            self.status = consts.AnalysisStatusCode.FAILED
        except Exception:
            if self.status == consts.AnalysisStatusCode.IN_PROGRESS:
                self._scan_api.close_scan_store(scan_summary={'reason': EndpointAnalysisEndReason.FAILED.value})
            self.status = consts.AnalysisStatusCode.FAILED
            raise
        finally:
            if self.status == consts.AnalysisStatusCode.IN_PROGRESS:
                self._scan_api.close_scan_store(scan_summary={'reason': EndpointAnalysisEndReason.DONE.value})
                self.status = consts.AnalysisStatusCode.CREATED
        return self.analysis_id

    def _create_scan(self):
        with open(os.path.join(self._metadata_dir, 'scanner_info.json')) as f:
            scanner_info = json.load(f)
        result = self._api.create_endpoint_scan(scanner_info)
        self.scan_id = result['scan_id']
        self.analysis_id = result['analysis_id']

    def _initialize_endpoint_api(self):
        if not self._scan_api:
            self._scan_api = EndpointScanApi(self.scan_id, self._api)

    def _send_host_info(self):
        logger.info('Sending host info')
        with open(os.path.join(self._metadata_dir, 'host_info.json')) as f:
            host_info = json.load(f)
        self._scan_api.send_host_info(host_info)

    def _send_processes_info(self):
        logger.info('Sending processes info')
        with open(os.path.join(self._metadata_dir, 'processes_info.json')) as f:
            processes_info = json.load(f)
        self._scan_api.send_processes_info(processes_info)

    def _send_scheduled_tasks_info(self):
        if not os.path.exists(os.path.join(self._metadata_dir, 'scheduled_tasks_info.json')):
            return
        logger.info('Sending scheduled tasks info')
        with open(os.path.join(self._metadata_dir, 'scheduled_tasks_info.json')) as f:
            scheduled_tasks_info = json.load(f)
        self._scan_api.send_scheduled_tasks_info(scheduled_tasks_info)

    def _send_loaded_modules_info(self):
        logger.info('Sending loaded modules info')
        for loaded_module_info_file in glob.glob(os.path.join(self._metadata_dir, '*_loaded_modules_info.json')):
            with open(loaded_module_info_file, 'r') as f:
                loaded_modules_info = json.load(f)

            pid = os.path.basename(loaded_module_info_file).split('_')[0]
            self._scan_api.send_loaded_modules_info(pid, loaded_modules_info)

    def _send_files_info_and_upload_required(self):
        logger.info('Sending files info and uploading required files')
        for files_info_file in glob.glob(os.path.join(self._metadata_dir, 'files_info_*.json')):
            with open(files_info_file, 'r') as f:
                files_info = json.load(f)

            files_to_upload = self._scan_api.send_files_info(files_info)

            for file_to_upload in files_to_upload:
                file_path = os.path.join(self._files_dir, file_to_upload + '.sample')
                if os.path.exists(file_path):
                    self._scan_api.upload_collected_binary(file_path, 'file-system')
                else:
                    logger.warning('File %s does not exist', file_path)

    def _send_module_differences(self):
        logger.info('Sending file module differences info')
        with open(os.path.join(self._metadata_dir, 'file_module_differences.json')) as f:
            file_module_differences = json.load(f)
        self._scan_api.send_file_module_differences(file_module_differences)

    def _send_injected_modules_info(self):
        logger.info('Sending injected modules info')
        with open(os.path.join(self._metadata_dir, 'injected_modules_info.json')) as f:
            injected_modules_info = json.load(f)
        self._scan_api.send_injected_modules_info(injected_modules_info)

    def _send_memory_module_dump_info_and_upload_required(self):
        logger.info('Sending memory module dump info')
        for memory_module_dump_info_file in glob.glob(os.path.join(self._metadata_dir,
                                                                   'memory_module_dump_info_*.json')):
            with open(memory_module_dump_info_file, 'r') as f:
                memory_module_dump_info = json.load(f)

            files_to_upload = self._scan_api.send_memory_module_dump_info(memory_module_dump_info)

            for file_to_upload in files_to_upload:
                memory_module_path = os.path.join(self._memory_modules_dir, file_to_upload + '.sample')
                fileless_path = os.path.join(self._fileless_dir, file_to_upload + '.sample')
                if os.path.exists(memory_module_path):
                    self._scan_api.upload_collected_binary(memory_module_path, 'memory')
                elif os.path.exists(fileless_path):
                    self._scan_api.upload_collected_binary(fileless_path, 'fileless')
                else:
                    logger.warning('File %s does not exist', file_to_upload + '.sample')
