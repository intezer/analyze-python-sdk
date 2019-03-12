import sys
import unittest

import responses

from intezer_sdk import consts
from intezer_sdk import errors
from intezer_sdk.analysis import Analysis
from intezer_sdk.api import set_global_api

try:
    from unittest.mock import mock_open
    from unittest.mock import patch
except ImportError:
    from mock import mock_open
    from mock import patch


class AnalysisSpec(unittest.TestCase):
    def setUp(self):

        self.full_url = consts.BASE_URL + consts.API_VERSION

        if sys.version_info[0] < 3:
            self.patch_prop = '__builtin__.open'
        else:
            self.patch_prop = 'builtins.open'

        # make access-token mock
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/get-access-token',
                     status=200,
                     json={'result': 'testtest'})
            set_global_api()

    def test_send_analysis_by_sha256_send_analysis_and_sets_status(self):
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

    def test_send_analysis_by_file_send_analysis_and_sets_status(self):
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

    def test_send_analysis_by_file_send_analysis_without_wait_and_get_status_finish(self):
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

    def test_send_analysis_by_file_send_analysis_with_pulling_and_get_status_finish(self):
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

    def test_analysis_by_sha256_and_file_send_analysis_and_raise_value_error(self):
        # Assert
        with self.assertRaises(ValueError):
            Analysis(file_hash='a', file_path='/test/test')

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
