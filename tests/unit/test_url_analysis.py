import uuid

import responses

from intezer_sdk import consts
from intezer_sdk import errors
from intezer_sdk.analysis import UrlAnalysis
from intezer_sdk.api import get_global_api
from intezer_sdk.consts import OnPremiseVersion
from tests.unit.base_test import BaseTest


class UrlAnalysisSpec(BaseTest):
    def test_get_analysis_by_id_analysis_object_when_latest_analysis_found(self):
        # Arrange
        analysis_id = 'analysis_id'
        submitted_url = 'https://url.com'
        analysis_report = {'analysis_id': analysis_id, 'submitted_url': submitted_url}

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url='{}/url/{}'.format(self.full_url, analysis_id),
                     status=200,
                     json={'result': analysis_report, 'status': 'succeeded'})

            # Act
            analysis = UrlAnalysis.from_analysis_id(analysis_id)

        self.assertIsNotNone(analysis)
        self.assertEqual(analysis_id, analysis.analysis_id)
        self.assertEqual(submitted_url, analysis.url)
        self.assertEqual(consts.AnalysisStatusCode.FINISHED, analysis.status)
        self.assertDictEqual(analysis_report, analysis.result())

    def test_get_analysis_by_id_in_progress(self):
        # Arrange
        analysis_id = 'analysis_id'

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url='{}/url/{}'.format(self.full_url, analysis_id),
                     status=202,
                     json={'status': consts.AnalysisStatusCode.IN_PROGRESS.value})

            # Act
            analysis = UrlAnalysis.from_analysis_id(analysis_id)

            # Assert
            self.assertEqual(consts.AnalysisStatusCode.IN_PROGRESS, analysis.status)
            self.assertEqual(analysis_id, analysis.analysis_id)

    def test_get_analysis_by_id_raises_when_analysis_failed(self):
        # Arrange
        analysis_id = 'analysis_id'

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url='{}/url/{}'.format(self.full_url, analysis_id),
                     status=200,
                     json={'status': consts.AnalysisStatusCode.FAILED.value})

            # Act
            with self.assertRaises(errors.AnalysisFailedError):
                UrlAnalysis.from_analysis_id(analysis_id)

    def test_send_perform_request_and_sets_analysis_status(self):
        # Arrange
        analysis_id = str(uuid.uuid4())
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/url',
                     status=201,
                     json={'result_url': '/url/{}'.format(analysis_id)})
            analysis = UrlAnalysis(url='https://intezer.com')

            # Act
            analysis.send()

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.CREATED)
        self.assertEqual(analysis_id, analysis.analysis_id)

    def test_send_fail_when_invalid_url(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/url',
                     status=400,
                     json={'error': 'Some error description'})
            analysis = UrlAnalysis(url='httpdddds://intezer.com')

            # Act
            with self.assertRaises(errors.ServerError):
                analysis.send()

    def test_send_fail_when_on_premise(self):
        # Arrange
        get_global_api().on_premise_version = OnPremiseVersion.V21_11

        # Act
        with self.assertRaises(errors.UnsupportedOnPremiseVersionError):
            _ = UrlAnalysis(url='httpdddds://intezer.com')

    def test_send_waits_to_compilation_when_requested(self):
        # Arrange
        analysis_id = str(uuid.uuid4())

        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/url',
                     status=201,
                     json={'result_url': '/url/{}'.format(analysis_id)})
            result = {'analysis_id': analysis_id}
            mock.add('GET',
                     url='{}/url/{}'.format(self.full_url, analysis_id),
                     status=200,
                     json={'result': result, 'status': 'succeeded'})
            analysis = UrlAnalysis('https://intezer.com')

            # Act
            analysis.send(wait=True)

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISHED)
        self.assertDictEqual(analysis.result(), result)

    def test_send_waits_to_compilation_when_requested_and_handles_failure(self):
        # Arrange
        analysis_id = str(uuid.uuid4())

        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/url',
                     status=201,
                     json={'result_url': '/url/{}'.format(analysis_id)})
            result = {'analysis_id': analysis_id}
            mock.add('GET',
                     url='{}/url/{}'.format(self.full_url, analysis_id),
                     status=200,
                     json={'result': result, 'status': 'failed'})
            analysis = UrlAnalysis('https://intezer.com')

            with self.assertRaises(errors.IntezerError):
                # Act
                analysis.send(wait=True)

        # Assert
        self.assertEqual(consts.AnalysisStatusCode.FAILED, analysis.status)

    def test_url_analysis_references_file_analysis(self):
        # Arrange
        url_analysis_id = str(uuid.uuid4())
        file_analysis_id = str(uuid.uuid4())
        url_result = {'analysis_id': url_analysis_id,
                      'downloaded_file': {
                          'analysis_id': file_analysis_id
                      }}
        file_analysis_report = {'analysis_id': file_analysis_id, 'sha256': 'hash'}

        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/url',
                     status=201,
                     json={'result_url': '/url/{}'.format(url_analysis_id)})
            mock.add('GET',
                     url='{}/url/{}'.format(self.full_url, url_analysis_id),
                     status=200,
                     json={'result': url_result, 'status': 'succeeded'})
            mock.add('GET',
                     url='{}/analyses/{}'.format(self.full_url, file_analysis_id),
                     status=200,
                     json={'result': file_analysis_report, 'status': 'succeeded'})
            analysis = UrlAnalysis('https://intezer.com')

            # Act
            analysis.send(wait=True)
            file_analysis = analysis.downloaded_file_analysis

            # Assert
            self.assertEqual(file_analysis.analysis_id, file_analysis_id)
            self.assertEqual(file_analysis.result(), file_analysis_report)

    def test_url_analysis_doesnt_reference_file_analysis_when_not_exists(self):
        # Arrange
        analysis_id = str(uuid.uuid4())
        result = {'analysis_id': analysis_id}

        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/url',
                     status=201,
                     json={'result_url': '/url/{}'.format(analysis_id)})
            mock.add('GET',
                     url='{}/url/{}'.format(self.full_url, analysis_id),
                     status=200,
                     json={'result': result, 'status': 'succeeded'})
            analysis = UrlAnalysis('https://intezer.com')

            # Act
            analysis.send(wait=True)

            # Assert
            self.assertIsNone(analysis.downloaded_file_analysis)

    def test_get_url_latest_analysis(self):
        # Arrange
        url = 'https://intezer.com'
        analysis_id = str(uuid.uuid4())
        get_analysis_result = {'analysis_id': analysis_id, 'submitted_url': url}
        fetch_history_result = {'analyses': [{'analysis_id': analysis_id, 'scanned_url': url, 'submitted_url': url}],
                                'total_count': 1}

        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/url-analyses/history',
                     status=200,
                     json=fetch_history_result)
            mock.add('GET',
                     url='{}/url/{}'.format(self.full_url, analysis_id),
                     status=200,
                     json={'result': get_analysis_result, 'status': 'succeeded'})


            # Act
            analysis = UrlAnalysis.from_latest_analysis(url)

            # Assert
            self.assertEqual(analysis.url, url)

    def test_get_url_latest_analysis_analyses_not_found(self):
        # Arrange
        url = 'https://intezer.com'
        fetch_history_result = {'analyses': [],
                                'total_count': 0}

        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/url-analyses/history',
                     status=200,
                     json=fetch_history_result)


            # Act
            analysis = UrlAnalysis.from_latest_analysis(url)

            # Assert
            self.assertIsNone(analysis)