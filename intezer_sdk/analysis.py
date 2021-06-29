import logging
import time
import typing
from http import HTTPStatus

from intezer_sdk import consts
from intezer_sdk import errors
from intezer_sdk.api import IntezerApi
from intezer_sdk.api import get_global_api
from intezer_sdk.consts import CodeItemType
from intezer_sdk.sub_analysis import SubAnalysis

logger = logging.getLogger(__name__)


class Analysis:
    def __init__(self,
                 file_path: str = None,
                 file_hash: str = None,
                 file_stream: typing.BinaryIO = None,
                 disable_dynamic_unpacking: bool = None,
                 disable_static_unpacking: bool = None,
                 api: IntezerApi = None,
                 file_name: str = None,
                 code_item_type: str = None) -> None:
        if [file_path, file_hash, file_stream].count(None) != 2:
            raise ValueError('Choose between file hash, file stream or file path analysis')

        if file_hash and code_item_type:
            logger.warning('Analyze by hash ignores code item type')

        if code_item_type and code_item_type not in [c.value for c in CodeItemType]:
            raise ValueError('Invalid code item type, possible code item types are: file, memory module')

        self.status = None
        self.analysis_id = None
        self._file_hash = file_hash
        self._disable_dynamic_unpacking = disable_dynamic_unpacking
        self._disable_static_unpacking = disable_static_unpacking
        self._file_path = file_path
        self._file_stream = file_stream
        self._file_name = file_name
        self._code_item_type = code_item_type
        self._report = None
        self._api = api or get_global_api()
        self._sub_analyses = None
        self._root_analysis = None

    def send(self, wait: typing.Union[bool, int] = False) -> None:
        if self.analysis_id:
            raise errors.AnalysisHasAlreadyBeenSent()

        if self._file_hash:
            self.analysis_id = self._api.analyze_by_hash(self._file_hash,
                                                         self._disable_dynamic_unpacking,
                                                         self._disable_static_unpacking)
        else:
            self.analysis_id = self._api.analyze_by_file(self._file_path,
                                                         self._file_stream,
                                                         disable_dynamic_unpacking=self._disable_dynamic_unpacking,
                                                         disable_static_unpacking=self._disable_static_unpacking,
                                                         file_name=self._file_name,
                                                         code_item_type=self._code_item_type)

        self.status = consts.AnalysisStatusCode.CREATED

        if wait:
            if isinstance(wait, int):
                self.wait_for_completion(wait, sleep_before_first_check=True)
            else:
                self.wait_for_completion(sleep_before_first_check=True)

    def wait_for_completion(self, interval: int = None, sleep_before_first_check=False):
        """
        Blocks until the analysis is completed
        :param interval: The interval to wait between checks
        :param sleep_before_first_check: Whether to sleep before the first status check 
        """
        if not interval:
            interval = consts.CHECK_STATUS_INTERVAL
        if self._is_analysis_running():
            if sleep_before_first_check:
                time.sleep(interval)
            status_code = self.check_status()

            while status_code != consts.AnalysisStatusCode.FINISH:
                time.sleep(interval)
                status_code = self.check_status()

    def check_status(self):
        if not self._is_analysis_running():
            raise errors.IntezerError('Analysis dont running')

        response = self._api.get_analysis_response(self.analysis_id)
        if response.status_code == HTTPStatus.OK:
            self._report = response.json()['result']
            self.status = consts.AnalysisStatusCode.FINISH
        elif response.status_code == HTTPStatus.ACCEPTED:
            self.status = consts.AnalysisStatusCode.IN_PROGRESS
        else:
            raise errors.IntezerError('Error in response status code:{}'.format(response.status_code))

        return self.status

    def result(self):
        if self._is_analysis_running():
            raise errors.AnalysisIsStillRunning()
        if not self._report:
            raise errors.ReportDoesNotExistError()

        return self._report

    def set_report(self, report: dict):
        if not report:
            raise ValueError('Report can not be None')

        self.analysis_id = report['analysis_id']
        self._report = report
        self.status = consts.AnalysisStatusCode.FINISH

    def _is_analysis_running(self):
        return self.status in (consts.AnalysisStatusCode.CREATED, consts.AnalysisStatusCode.IN_PROGRESS)

    def get_sub_analyses(self):
        if self._sub_analyses is None and self.analysis_id:
            self._init_sub_analyses()
        return self._sub_analyses

    def get_root_analysis(self):
        if self._root_analysis is None and self.analysis_id:
            self._init_sub_analyses()
        return self._root_analysis

    def _init_sub_analyses(self):
        all_sub_analysis = self._api.get_sub_analyses_by_id(self.analysis_id)
        self._sub_analyses = []
        for sub_analysis in all_sub_analysis:
            sub_analysis_object = SubAnalysis(sub_analysis['sub_analysis_id'],
                                              self.analysis_id,
                                              sub_analysis['sha256'],
                                              sub_analysis['source'],
                                              api=self._api)
            if sub_analysis_object.source == 'root':
                self._root_analysis = sub_analysis_object
            else:
                self._sub_analyses.append(sub_analysis_object)

    def download_file(self, path: str):
        self._api.download_file_by_sha256(self.result()['sha256'], path)


def get_latest_analysis(file_hash: str, api: IntezerApi = None) -> typing.Optional[Analysis]:
    api = api or get_global_api()
    analysis_report = api.get_latest_analysis(file_hash)

    if not analysis_report:
        return None

    analysis = Analysis(file_hash=file_hash, api=api)
    analysis.set_report(analysis_report)

    return analysis


def get_analysis_by_id(analysis_id: str, api: IntezerApi = None) -> typing.Optional[Analysis]:
    api = api or get_global_api()
    response = api.get_analysis_response(analysis_id).json()

    if response['status'] in (consts.AnalysisStatusCode.IN_PROGRESS.value, consts.AnalysisStatusCode.CREATED.value):
        raise errors.AnalysisIsStillRunning()

    analysis_report = response.get('result')

    if not analysis_report:
        return None

    analysis = Analysis(file_hash=analysis_report['sha256'], api=api)
    analysis.set_report(analysis_report)

    return analysis
