from unittest.mock import mock_open
from unittest.mock import patch

import responses

from intezer_sdk import consts
from intezer_sdk import errors
from intezer_sdk.analysis import Analysis
from intezer_sdk.analysis import get_latest_analysis
from intezer_sdk.api import get_global_api
from intezer_sdk.api import set_global_api
from tests.unit.base_test import BaseTest


class AnalysisSpec(BaseTest):
    def setUp(self):
        super(AnalysisSpec, self).setUp()

        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/get-access-token',
                     status=200,
                     json={'result': 'access-token'})
            set_global_api()
            get_global_api().set_session()

    def test_send_analysis_by_sha256_sent_analysis_and_sets_status(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/analyze-by-hash',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            analysis = Analysis(file_hash='a' * 64)

            # Act
            analysis.send()

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.CREATED)

    def test_send_analysis_by_file_sent_analysis_and_sets_status(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/analyze',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            analysis = Analysis(file_path='a')

            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send()

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.CREATED)

    def test_analysis_by_file_wrong_code_item_type(self):
        # Act + Assert
        with self.assertRaises(ValueError):
            Analysis(file_path='a', code_item_type='anderson_paak')

    def test_analysis_by_file_correct_code_item_type(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/analyze',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            analysis = Analysis(file_path='a',
                                code_item_type='memory_module')

            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send()

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.CREATED)

    def test_send_analysis_by_file_with_file_stream_sent_analysis(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/analyze',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            analysis = Analysis(file_stream=__file__)

            # Act
            analysis.send()

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.CREATED)

    def test_send_analysis_by_file_sends_analysis_with_waits_to_compilation_when_requested(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/analyze',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=self.full_url + '/analyses/asd',
                     status=200,
                     json={'result': 'report'})
            analysis = Analysis(file_path='a')

            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISH)

    def test_send_analysis_by_file_sent_analysis_without_wait_and_get_status_finish(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/analyze',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=self.full_url + '/analyses/asd',
                     status=200,
                     json={'result': 'report'})
            analysis = Analysis(file_path='a')

            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send()
                analysis.wait_for_completion()

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISH)

    def test_send_analysis_by_file_sent_analysis_with_pulling_and_get_status_finish(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/analyze',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=self.full_url + '/analyses/asd',
                     status=202)
            mock.add('GET',
                     url=self.full_url + '/analyses/asd',
                     status=202)
            mock.add('GET',
                     url=self.full_url + '/analyses/asd',
                     status=200,
                     json={'result': 'report'})
            analysis = Analysis(file_path='a')

            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send()
                analysis.check_status()
                analysis.check_status()
                analysis.check_status()

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISH)

    def test_send_analysis_by_file_and_get_report(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/analyze',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=self.full_url + '/analyses/asd',
                     status=200,
                     json={'result': 'report'})
            analysis = Analysis(file_path='a')
            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISH)
        self.assertEqual(analysis.result(), 'report')

    def test_send_analysis_by_sha256_that_dont_exist_raise_error(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/analyze-by-hash',
                     status=404)
            analysis = Analysis(file_hash='a' * 64)
            # Act + Assert
            with self.assertRaises(errors.HashDoesNotExistError):
                analysis.send()

    def test_send_analysis_while_running_raise_error(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/analyze-by-hash',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            analysis = Analysis(file_hash='a' * 64)
            # Act + Assert
            with self.assertRaises(errors.AnalysisHasAlreadyBeenSent):
                analysis.send()
                analysis.send()

    def test_send_analysis_that_running_on_server_raise_error(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/analyze-by-hash',
                     status=409,
                     json={'result_url': 'a/sd/asd'})
            analysis = Analysis(file_hash='a' * 64)
            # Act + Assert
            with self.assertRaises(errors.AnalysisIsAlreadyRunning):
                analysis.send()

    def test_analysis_raise_value_error_when_no_file_option_given(self):
        # Assert
        with self.assertRaises(ValueError):
            Analysis()

    def test_analysis_by_sha256_and_file_sent_analysis_and_raise_value_error(self):
        # Assert
        with self.assertRaises(ValueError):
            Analysis(file_hash='a', file_path='/test/test')

    def test_analysis_by_sha256_raise_value_error_when_file_path_and_file_stream_given(self):
        # Assert
        with self.assertRaises(ValueError):
            Analysis(file_stream=__file__, file_path='/test/test')

    def test_analysis_by_sha256_raise_value_error_when_sha256_file_path_and_file_stream_given(self):
        # Assert
        with self.assertRaises(ValueError):
            Analysis(file_hash='a', file_stream=__file__, file_path='/test/test')

    def test_analysis_get_report_for_not_finish_analyze_raise_error(self):
        # Arrange
        analysis = Analysis(file_hash='a')
        # Act + Assert
        with self.assertRaises(errors.ReportDoesNotExistError):
            analysis.result()

    def test_analysis_check_status_before_send_raise_error(self):
        # Arrange
        analysis = Analysis(file_hash='a')

        # Act + Assert
        with self.assertRaises(errors.IntezerError):
            analysis.check_status()

    def test_analysis_check_status_after_analysis_finish_raise_error(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/analyze',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=self.full_url + '/analyses/asd',
                     status=200,
                     json={'result': 'report'})
            analysis = Analysis(file_path='a')

            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)

            # Assert
            with self.assertRaises(errors.IntezerError):
                analysis.check_status()

    def test_get_latest_analysis_none_when_no_analysis_found(self):
        # Arrange
        file_hash = 'hash'

        with responses.RequestsMock() as mock:
            mock.add('GET', url='{}/files/{}'.format(self.full_url, file_hash), status=404)

            # Act
            analysis = get_latest_analysis(file_hash)

        self.assertIsNone(analysis)

    def test_get_latest_analysis_analysis_object_when_latest_analysis_found(self):
        # Arrange
        file_hash = 'hash'
        analysis_id = 'analysis_id'
        analysis_report = {'analysis_id': analysis_id}

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url='{}/files/{}'.format(self.full_url, file_hash),
                     status=200,
                     json={'result': analysis_report})

            # Act
            analysis = get_latest_analysis(file_hash)

        self.assertIsNotNone(analysis)
        self.assertEqual(analysis_id, analysis.analysis_id)
        self.assertEqual(consts.AnalysisStatusCode.FINISH, analysis.status)
        self.assertDictEqual(analysis_report, analysis.result())
