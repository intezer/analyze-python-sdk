import unittest

import responses
from mock import mock_open
from mock import patch

from intezer_sdk.analysis import Analysis
from intezer_sdk.consts import AnalysisStatusCode
from intezer_sdk.exceptions import AnalysisAlreadyBeenSent
from intezer_sdk.exceptions import AnalysisAlreadyRunning
from intezer_sdk.exceptions import HashDoesNotExistError
from intezer_sdk.exceptions import IntezerError
from intezer_sdk.exceptions import ReportDoesNotExistError


class AnalysisSpec(unittest.TestCase):
    def setUp(self):
        pass

    def test_send_analysis_by_sha256_send_analysis_and_sets_status(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url='https://analyze.intezer.com/api/v2-0/analyze-by-hash',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            mock.add('POST',
                     url='https://analyze.intezer.com/api/v2-0/get-access-token',
                     status=200,
                     json={'result': 'testtest'})
            analysis = Analysis(file_hash='a' * 64)

            # Act
            analysis.send()

        # Assert
        self.assertEqual(analysis.status, AnalysisStatusCode.send)

    def test_send_analysis_by_file_send_analysis_and_sets_status(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url='https://analyze.intezer.com/api/v2-0/analyze',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            mock.add('POST',
                     url='https://analyze.intezer.com/api/v2-0/get-access-token',
                     status=200,
                     json={'result': 'testtest'})
            analysis = Analysis(file_path='a')

            with patch("__builtin__.open", mock_open(read_data="data")) as mock_file:
                assert open("a").read() == "data"
                mock_file.assert_called_with("a")

                # Act
                analysis.send()

        # Assert
        self.assertEqual(analysis.status, AnalysisStatusCode.send)

    def test_send_analysis_by_file_send_analysis_with_wait_and_get_status_finish(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url='https://analyze.intezer.com/api/v2-0/analyze',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            mock.add('POST',
                     url='https://analyze.intezer.com/api/v2-0/get-access-token',
                     status=200,
                     json={'result': 'testtest'})
            mock.add('GET',
                     url='https://analyze.intezer.com/api/v2-0/analyses/asd',
                     status=200,
                     json={'result': 'report'})
            analysis = Analysis(file_path='a')

            with patch("__builtin__.open", mock_open(read_data="data")) as mock_file:
                assert open("a").read() == "data"
                mock_file.assert_called_with("a")

                # Act
                analysis.send(wait=True)

        # Assert
        self.assertEqual(analysis.status, AnalysisStatusCode.finish)

    def test_send_analysis_by_file_send_analysis_without_wait_and_get_status_finish(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url='https://analyze.intezer.com/api/v2-0/analyze',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            mock.add('POST',
                     url='https://analyze.intezer.com/api/v2-0/get-access-token',
                     status=200,
                     json={'result': 'testtest'})
            mock.add('GET',
                     url='https://analyze.intezer.com/api/v2-0/analyses/asd',
                     status=200,
                     json={'result': 'report'})
            analysis = Analysis(file_path='a')

            with patch("__builtin__.open", mock_open(read_data="data")) as mock_file:
                assert open("a").read() == "data"
                mock_file.assert_called_with("a")

                # Act
                analysis.send()
                analysis.wait_for_completion()

        # Assert
        self.assertEqual(analysis.status, AnalysisStatusCode.finish)

    def test_send_analysis_by_file_send_analysis_with_pulling_and_get_status_finish(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url='https://analyze.intezer.com/api/v2-0/analyze',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            mock.add('POST',
                     url='https://analyze.intezer.com/api/v2-0/get-access-token',
                     status=200,
                     json={'result': 'testtest'})
            mock.add('GET',
                     url='https://analyze.intezer.com/api/v2-0/analyses/asd',
                     status=202)
            mock.add('GET',
                     url='https://analyze.intezer.com/api/v2-0/analyses/asd',
                     status=202)
            mock.add('GET',
                     url='https://analyze.intezer.com/api/v2-0/analyses/asd',
                     status=200,
                     json={'result': 'report'})

            analysis = Analysis(file_path='a')

            with patch("__builtin__.open", mock_open(read_data="data")) as mock_file:
                assert open("a").read() == "data"
                mock_file.assert_called_with("a")

                # Act
                analysis.send()
                analysis.check_status()
                analysis.check_status()
                analysis.check_status()

        # Assert
        self.assertEqual(analysis.status, AnalysisStatusCode.finish)

    def test_send_analysis_by_file_and_get_report(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url='https://analyze.intezer.com/api/v2-0/analyze',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            mock.add('POST',
                     url='https://analyze.intezer.com/api/v2-0/get-access-token',
                     status=200,
                     json={'result': 'testtest'})
            mock.add('GET',
                     url='https://analyze.intezer.com/api/v2-0/analyses/asd',
                     status=200,
                     json={'result': 'report'})
            analysis = Analysis(file_path='a')

            with patch("__builtin__.open", mock_open(read_data="data")) as mock_file:
                assert open("a").read() == "data"
                mock_file.assert_called_with("a")

                # Act
                analysis.send(wait=True)

        # Assert
        self.assertEqual(analysis.status, AnalysisStatusCode.finish)
        self.assertEqual(analysis.result(), 'report')

    def test_send_analysis_by_sha256_that_dont_exist_raise_error(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url='https://analyze.intezer.com/api/v2-0/analyze-by-hash',
                     status=404)
            mock.add('POST',
                     url='https://analyze.intezer.com/api/v2-0/get-access-token',
                     status=200,
                     json={'result': 'testtest'})
            analysis = Analysis(file_hash='a' * 64)

            # Act + Assert
            with self.assertRaises(HashDoesNotExistError):
                analysis.send()

    def test_send_analysis_while_running_raise_error(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url='https://analyze.intezer.com/api/v2-0/analyze-by-hash',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            mock.add('POST',
                     url='https://analyze.intezer.com/api/v2-0/get-access-token',
                     status=200,
                     json={'result': 'testtest'})
            analysis = Analysis(file_hash='a' * 64)

            # Act + Assert
            with self.assertRaises(AnalysisAlreadyBeenSent):
                analysis.send()
                analysis.send()

    def test_send_analysis_that_running_on_server_raise_error(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url='https://analyze.intezer.com/api/v2-0/analyze-by-hash',
                     status=409,
                     json={'result_url': 'a/sd/asd'})
            mock.add('POST',
                     url='https://analyze.intezer.com/api/v2-0/get-access-token',
                     status=200,
                     json={'result': 'testtest'})
            analysis = Analysis(file_hash='a' * 64)

            # Act + Assert
            with self.assertRaises(AnalysisAlreadyRunning):
                analysis.send()

    def test_analysis_by_sha256_and_file_send_analysis_and_raise_value_error(self):
        # Assert
        with self.assertRaises(ValueError):
            Analysis(file_hash='a', file_path='/test/test')

    def test_analysis_get_report_for_not_finish_analyze_raise_error(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url='https://analyze.intezer.com/api/v2-0/get-access-token',
                     status=200,
                     json={'result': 'testtest'})
            analysis = Analysis(file_hash='a')
            # Act + Assert
            with self.assertRaises(ReportDoesNotExistError):
                analysis.result()

    def test_analysis_check_status_before_send_raise_error(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url='https://analyze.intezer.com/api/v2-0/get-access-token',
                     status=200,
                     json={'result': 'testtest'})
            analysis = Analysis(file_hash='a')
            # Act + Assert
            with self.assertRaises(IntezerError):
                analysis.check_status()

    def test_analysis_check_status_after_analysis_finish_raise_error(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url='https://analyze.intezer.com/api/v2-0/analyze',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            mock.add('POST',
                     url='https://analyze.intezer.com/api/v2-0/get-access-token',
                     status=200,
                     json={'result': 'testtest'})
            mock.add('GET',
                     url='https://analyze.intezer.com/api/v2-0/analyses/asd',
                     status=200,
                     json={'result': 'report'})
            analysis = Analysis(file_path='a')

            with patch("__builtin__.open", mock_open(read_data="data")) as mock_file:
                assert open("a").read() == "data"
                mock_file.assert_called_with("a")

                # Act
                analysis.send(wait=True)

            # Assert
            with self.assertRaises(IntezerError):
                analysis.check_status()
