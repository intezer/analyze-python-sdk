import concurrent.futures
import glob
import json
import logging
import os
import pathlib
from typing import List

from intezer_sdk import consts
from intezer_sdk._api import IntezerApi
from intezer_sdk._endpoint_analysis_api import EndpointScanApi
from intezer_sdk.api import IntezerApiClient
from intezer_sdk.api import get_global_api
from intezer_sdk.base_analysis import Analysis
from intezer_sdk.consts import EndpointAnalysisEndReason
from intezer_sdk.sub_analysis import SubAnalysis

logger = logging.getLogger(__name__)


class EndpointAnalysis(Analysis):
    """
    EndpointAnalysis is a class for analyzing endpoints. It is a subclass of the Analysis class and requires an API connection to Intezer.
    """

    def __init__(self,
                 api: IntezerApiClient = None,
                 scan_api: EndpointScanApi = None,
                 offline_scan_directory: str = None):
        """
        Initializes an EndpointAnalysis object.
        Supports offline scan mode, run Scanner.exe with the '-o' flag to generate the offline scan directory.

        :param api: The API connection to Intezer.
        :param scan_api: The API connection to Intezer for endpoint scans.
        :param offline_scan_directory: The directory of the offline scan. (example: C:\scans\scan_%computername%_%time%)
        """
        super().__init__(api)
        self._scan_api = scan_api
        if offline_scan_directory:
            files_dir = os.path.join(offline_scan_directory, '..', 'files')
            fileless_dir = os.path.join(offline_scan_directory, '..', 'fileless')
            memory_modules_dir = os.path.join(offline_scan_directory, '..', 'memory_modules')
            self._offline_scan_directory = pathlib.Path(offline_scan_directory)
            self._files_dir = pathlib.Path(files_dir)
            self._fileless_dir = pathlib.Path(fileless_dir)
            self._memory_modules_dir = pathlib.Path(memory_modules_dir)

        self._sub_analyses: List[SubAnalysis] = []
        self._scan_id = None

    @classmethod
    def from_analysis_id(cls, analysis_id: str, api: IntezerApiClient = None):
        """
        Returns an EndpointAnalysis instance with the given analysis ID.
        Returns None when analysis doesn't exist.

        :param analysis_id: The ID of the analysis to retrieve.
        :param api: The API connection to Intezer.
        :return: An EndpointAnalysis instance with the given analysis ID.
        """
        response = IntezerApi(api or get_global_api()).get_endpoint_analysis_response(analysis_id, True)
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
                                              api=self._api.api,
                                              verdict=sub_analysis['verdict'])
            self._sub_analyses.append(sub_analysis_object)

    def _send_analyze_to_api(self, **additional_parameters) -> str:
        try:
            if not self._offline_scan_directory:
                raise ValueError('Scan directory is not set')
            if not os.path.isdir(self._offline_scan_directory):
                raise ValueError('Scan directory does not exist')
            if not os.path.isdir(self._files_dir):
                raise ValueError('Files directory does not exist')
            if not os.path.isdir(self._fileless_dir):
                raise ValueError('Fileless directory does not exist')
            if not os.path.isdir(self._memory_modules_dir):
                raise ValueError('Memory modules directory does not exist')

            self._scan_id, self.analysis_id = self._create_scan()

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
                logger.info(f'Endpoint analysis: {self.analysis_id}, upload was interrupted by user. Ending scan.')
                self._scan_api.end_scan(scan_summary={'reason': EndpointAnalysisEndReason.INTERRUPTED.value})
            self.status = consts.AnalysisStatusCode.FAILED
            raise
        except Exception:
            if self.status == consts.AnalysisStatusCode.IN_PROGRESS:
                logger.info(f'Endpoint analysis: {self.analysis_id}, encountered an error. Ending scan.')
                self._scan_api.end_scan(scan_summary={'reason': EndpointAnalysisEndReason.FAILED.value})
            self.status = consts.AnalysisStatusCode.FAILED
            raise

        self._scan_api.end_scan(scan_summary={'reason': EndpointAnalysisEndReason.DONE.value})
        self.status = consts.AnalysisStatusCode.CREATED

        return self.analysis_id

    def _create_scan(self):
        with open(os.path.join(self._offline_scan_directory, 'scanner_info.json'), encoding='utf-8') as f:
            scanner_info = json.load(f)
        result = self._api.create_endpoint_scan(scanner_info)
        scan_id = result['scan_id']
        analysis_id = result['analysis_id']
        return scan_id, analysis_id

    def _initialize_endpoint_api(self):
        if not self._scan_api:
            self._scan_api = EndpointScanApi(self._scan_id, self._api.api)

    def _send_host_info(self):
        logger.info(f'Endpoint analysis: {self.analysis_id}, uploading host info')
        with open(os.path.join(self._offline_scan_directory, 'host_info.json'), encoding='utf-8') as f:
            host_info = json.load(f)
        self._scan_api.send_host_info(host_info)

    def _send_processes_info(self):
        logger.info(f'Endpoint analysis: {self.analysis_id}, uploading processes info')
        with open(os.path.join(self._offline_scan_directory, 'processes_info.json'), encoding='utf-8') as f:
            processes_info = json.load(f)
        self._scan_api.send_processes_info(processes_info)

    def _send_scheduled_tasks_info(self):
        scheduled_tasks_info_path = os.path.join(self._offline_scan_directory, 'scheduled_tasks_info.json')
        if not os.path.isfile(scheduled_tasks_info_path):
            return
        logger.info(f'Endpoint analysis: {self.analysis_id}, uploading scheduled tasks info')
        try:
            with open(scheduled_tasks_info_path, encoding='utf-8') as f:
                scheduled_tasks_info = json.load(f)
            self._scan_api.send_scheduled_tasks_info(scheduled_tasks_info)
        except BaseException:
            logger.warning(f'Endpoint analysis: {self.analysis_id}, failed to upload scheduled tasks info')

    def _send_loaded_modules_info(self):
        logger.info(f'Endpoint analysis: {self.analysis_id}, uploading loaded modules info')
        for loaded_module_info_file in glob.glob(os.path.join(self._offline_scan_directory,
                                                              '*_loaded_modules_info.json')):
            with open(loaded_module_info_file, encoding='utf-8') as f:
                loaded_modules_info = json.load(f)

            pid = os.path.basename(loaded_module_info_file).split('_', maxsplit=1)[0]
            self._scan_api.send_loaded_modules_info(pid, loaded_modules_info)

    def _send_files_info_and_upload_required(self):
        logger.info(f'Endpoint analysis: {self.analysis_id}, uploading files info and uploading required files')
        with concurrent.futures.ThreadPoolExecutor() as executor:
            for files_info_file in glob.glob(os.path.join(self._offline_scan_directory, 'files_info_*.json')):

                logger.debug(f'Endpoint analysis: {self.analysis_id}, uploading {files_info_file}')
                with open(files_info_file, encoding='utf-8') as f:
                    files_info = json.load(f)
                files_to_upload = self._scan_api.send_files_info(files_info)

                futures = []
                for file_to_upload in files_to_upload:
                    file_path = os.path.join(self._files_dir, f'{file_to_upload}.sample')
                    if os.path.isfile(file_path):
                        futures.append(executor.submit(self._scan_api.upload_collected_binary,
                                                       file_path,
                                                       'file-system'))
                    else:
                        logger.warning(f'Endpoint analysis: {self.analysis_id}, file {file_path} does not exist')
                for future in concurrent.futures.as_completed(futures):
                    future.result()

    def _send_module_differences(self):
        logger.info(f'Endpoint analysis: {self.analysis_id}, uploading file module differences info')
        with open(os.path.join(self._offline_scan_directory, 'file_module_differences.json'), encoding='utf-8') as f:
            file_module_differences = json.load(f)
        self._scan_api.send_file_module_differences(file_module_differences)

    def _send_injected_modules_info(self):
        logger.info(f'Endpoint analysis: {self.analysis_id}, uploading injected modules info')
        with open(os.path.join(self._offline_scan_directory, 'injected_modules_info.json'), encoding='utf-8') as f:
            injected_modules_info = json.load(f)
        self._scan_api.send_injected_modules_info(injected_modules_info)

    def _send_memory_module_dump_info_and_upload_required(self):
        logger.info(f'Endpoint analysis: {self.analysis_id}, uploading memory module dump info')
        with concurrent.futures.ThreadPoolExecutor() as executor:
            for memory_module_dump_info_file in glob.glob(os.path.join(self._offline_scan_directory,
                                                                       'memory_module_dump_info_*.json')):

                logger.debug(f'Endpoint analysis: {self.analysis_id}, uploading {memory_module_dump_info_file}')
                with open(memory_module_dump_info_file, encoding='utf-8') as f:
                    memory_module_dump_info = json.load(f)
                files_to_upload = self._scan_api.send_memory_module_dump_info(memory_module_dump_info)

                futures = []
                for file_to_upload in files_to_upload:
                    memory_module_path = os.path.join(self._memory_modules_dir, f'{file_to_upload}.sample')
                    fileless_path = os.path.join(self._fileless_dir, f'{file_to_upload}.sample')
                    if os.path.isfile(memory_module_path):
                        futures.append(executor.submit(self._scan_api.upload_collected_binary,
                                                       memory_module_path,
                                                       'memory'))
                    elif os.path.isfile(fileless_path):
                        futures.append(executor.submit(self._scan_api.upload_collected_binary,
                                                       fileless_path,
                                                       'fileless'))
                    else:
                        logger.warning(f'Endpoint analysis: {self.analysis_id}, file {file_to_upload}.sample does not exist')
                for future in concurrent.futures.as_completed(futures):
                    future.result()
