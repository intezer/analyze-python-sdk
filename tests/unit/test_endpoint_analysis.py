import uuid
from http import HTTPStatus

import responses

from intezer_sdk import consts
from intezer_sdk import errors
from intezer_sdk.endpoint_analysis import EndpointAnalysis
from tests.unit.base_test import BaseTest


class EndpointAnalysisSpec(BaseTest):
    def test_analysis_in_progress(self):
        # Arrange
        analysis_id = str(uuid.uuid4())
        result = {'status': 'in_progress'}

        with responses.RequestsMock() as mock:
            mock.add('GET', url=f'{self.full_url}/endpoint-analyses/{analysis_id}', status=HTTPStatus.ACCEPTED,
                     json=result)
            # Act
            analysis = EndpointAnalysis.from_analysis_id(analysis_id)

        # Assert
        self.assertIsNotNone(analysis)
        self.assertEqual(analysis_id, analysis.analysis_id)
        self.assertEqual(consts.AnalysisStatusCode.IN_PROGRESS, analysis.status)

    def test_wait_for_completion(self):
        # Arrange
        analysis_id = str(uuid.uuid4())
        in_progress_result = {
            'status': 'in_progress',
            'result_url': 'foo'
        }
        success_result = {
            'status': 'succeeded',
            'result': {
                'analysis_id': analysis_id,
                'scan_status': 'done'
            }
        }

        with responses.RequestsMock() as mock:
            mock.add('GET', url=f'{self.full_url}/endpoint-analyses/{analysis_id}', status=HTTPStatus.ACCEPTED,
                     json=in_progress_result)
            mock.add('GET', url=f'{self.full_url}/endpoint-analyses/{analysis_id}', status=HTTPStatus.OK,
                     json=success_result)
            # Act
            analysis = EndpointAnalysis.from_analysis_id(analysis_id)
            analysis.wait_for_completion(sleep_before_first_check=False)

        # Assert
        self.assertIsNotNone(analysis)
        self.assertEqual(consts.AnalysisStatusCode.FINISHED, analysis.status)

    def test_analysis_done(self):
        # Arrange
        analysis_id = str(uuid.uuid4())
        result = {
            'status': 'succeeded',
            'result': {
                'analysis_id': analysis_id,
                'scan_status': 'done',
                'verdict': 'malicious',
            }
        }

        with responses.RequestsMock() as mock:
            mock.add('GET', url=f'{self.full_url}/endpoint-analyses/{analysis_id}', status=HTTPStatus.OK, json=result)
            # Act
            analysis = EndpointAnalysis.from_analysis_id(analysis_id)

        # Assert
        self.assertIsNotNone(analysis)
        self.assertEqual(analysis_id, analysis.analysis_id)
        self.assertEqual(consts.AnalysisStatusCode.FINISHED, analysis.status)
        self.assertEqual('malicious', analysis.verdict)
        self.assertDictEqual(result['result'], analysis.result())

    def test_analysis_failed(self):
        # Arrange
        analysis_id = str(uuid.uuid4())
        result = {
            'status': 'failed',
        }

        with responses.RequestsMock() as mock:
            mock.add('GET', url=f'{self.full_url}/endpoint-analyses/{analysis_id}', status=HTTPStatus.OK,
                     json=result)

            # Act and Assert
            with self.assertRaises(errors.AnalysisFailedError):
                EndpointAnalysis.from_analysis_id(analysis_id)

    def test_analysis_not_found(self):
        # Arrange
        analysis_id = str(uuid.uuid4())

        with responses.RequestsMock() as mock:
            mock.add('GET', url=f'{self.full_url}/endpoint-analyses/{analysis_id}', status=HTTPStatus.NOT_FOUND)

            # Act
            analysis = EndpointAnalysis.from_analysis_id(analysis_id)

        # Assert
        self.assertIsNone(analysis)

    def test_get_sub_analyses(self):
        # Arrange
        analysis_id = str(uuid.uuid4())
        sub_analysis_id = str(uuid.uuid4())
        analysis = EndpointAnalysis()
        analysis.status = consts.AnalysisStatusCode.FINISHED
        analysis.analysis_id = analysis_id
        sha256 = 'a' * 64
        verdict = 'malicious'
        result = {
            'sub_analyses': [
                {'sub_analysis_id': sub_analysis_id,
                 'source': 'endpoint',
                 'sha256': sha256,
                 'verdict': verdict}
            ]
        }

        with responses.RequestsMock() as mock:
            mock.add('GET', url=f'{self.full_url}/endpoint-analyses/{analysis_id}/sub-analyses', status=HTTPStatus.OK,
                     json=result)

            sub_analyses = analysis.get_sub_analyses()[0]

        # Assert
        self.assertEqual(sub_analysis_id, sub_analyses.analysis_id)
        self.assertEqual(verdict, sub_analyses.verdict)
        self.assertEqual(sha256, sub_analyses.sha256)
