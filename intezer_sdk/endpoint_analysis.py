from http import HTTPStatus
from typing import List

from intezer_sdk import consts
from intezer_sdk import errors
from intezer_sdk.api import IntezerApi
from intezer_sdk.api import get_global_api
from intezer_sdk.base_analysis import Analysis
from intezer_sdk.sub_analysis import SubAnalysis


class EndpointAnalysis(Analysis):
    def __init__(self, api: IntezerApi = None):
        super().__init__(api)
        self._sub_analyses: List[SubAnalysis] = []

    @classmethod
    def from_analysis_id(cls, analysis_id: str, api: IntezerApi = None):
        api = api or get_global_api()
        response = api.get_endpoint_analysis_response(analysis_id, True)
        if response.status_code == HTTPStatus.NOT_FOUND:
            return None

        response_json = response.json()
        status = response_json['status']
        if status == consts.AnalysisStatusCode.FAILED.value:
            raise errors.AnalysisFailedError()

        analysis = EndpointAnalysis(api=api)
        if status != 'succeeded':
            analysis.status = consts.AnalysisStatusCode(status)
            analysis.analysis_id = analysis_id
        else:
            analysis_report = response_json.get('result')
            analysis.set_report(analysis_report)

        return analysis

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


def _assert_analysis_status(response: dict):
    if response['status'] in (consts.AnalysisStatusCode.IN_PROGRESS.value,
                              consts.AnalysisStatusCode.QUEUED.value):
        raise errors.AnalysisIsStillRunningError()
    if response['status'] == consts.AnalysisStatusCode.FAILED.value:
        raise errors.AnalysisFailedError()
