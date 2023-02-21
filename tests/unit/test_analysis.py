import datetime
import io
import json
import os
import tempfile
import time
import uuid
from http import HTTPStatus
from unittest.mock import mock_open
from unittest.mock import patch

import requests
import responses

from intezer_sdk import consts
from intezer_sdk import errors
from intezer_sdk.analysis import FileAnalysis
from intezer_sdk.api import get_global_api
from intezer_sdk.consts import OnPremiseVersion
from intezer_sdk.endpoint_analysis import EndpointAnalysis
from intezer_sdk.sub_analysis import SubAnalysis
from tests.unit.base_test import BaseTest


class FileAnalysisSpec(BaseTest):

    def test_send_analysis_by_sha256_sent_analysis_and_sets_status(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze-by-hash',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            analysis = FileAnalysis(file_hash='a' * 64)

            # Act
            analysis.send()

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.CREATED)

    def test_send_analysis_by_file_sent_analysis_and_sets_status(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            analysis = FileAnalysis(file_path='a')

            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send()

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.CREATED)

    def test_analysis_by_file_wrong_code_item_type(self):
        # Act + Assert
        with self.assertRaises(ValueError):
            FileAnalysis(file_path='a', code_item_type='anderson_paak')

    def test_analysis_by_file_correct_code_item_type(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            analysis = FileAnalysis(file_path='a',
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
                     url=f'{self.full_url}/analyze',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            analysis = FileAnalysis(file_stream=__file__)

            # Act
            analysis.send()

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.CREATED)

    def test_send_analysis_by_file_sends_analysis_with_waits_to_compilation_when_requested(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd',
                     status=HTTPStatus.OK,
                     json={'result': {'analysis_id': 'asd'}, 'status': 'succeeded'})
            analysis = FileAnalysis(file_path='a')

            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISHED)

    def test_send_analysis_by_file_sends_analysis_and_waits_specific_time_until_compilation(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd',
                     status=HTTPStatus.OK,
                     json={'result': {'analysis_id': 'asd'}, 'status': 'succeeded'})
            analysis = FileAnalysis(file_path='a')
            wait = 1

            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                start = datetime.datetime.utcnow()
                analysis.send(wait=wait)
                duration = (datetime.datetime.utcnow() - start).total_seconds()

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISHED)
        self.assertGreater(duration, wait)

    def test_send_analysis_by_file_sent_analysis_without_wait_and_get_status_finish(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd',
                     status=HTTPStatus.OK,
                     json={'result': {'analysis_id': 'asd'}, 'status': 'succeeded'})
            analysis = FileAnalysis(file_path='a')

            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send()
                analysis.wait_for_completion()

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISHED)

    def test_send_analysis_by_file_sent_analysis_with_pulling_and_get_status_finish(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd',
                     status=202)
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd',
                     status=202)
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd',
                     status=HTTPStatus.OK,
                     json={'result': {'analysis_id': 'asd'}, 'status': 'succeeded'})
            analysis = FileAnalysis(file_path='a')

            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send()
                analysis.check_status()
                analysis.check_status()
                analysis.check_status()

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISHED)

    def test_send_analysis_by_file_and_get_report(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd',
                     status=HTTPStatus.OK,
                     json={'result': {'analysis_id': 'asd'}, 'status': 'succeeded'})
            analysis = FileAnalysis(file_path='a')
            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISHED)
        self.assertDictEqual({'analysis_id': 'asd'}, analysis.result())

    def test_send_analysis_by_download_url_and_get_report(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze-by-url',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd',
                     status=HTTPStatus.OK,
                     json={'result': {'analysis_id': 'asd'}, 'status': 'succeeded'})
            analysis = FileAnalysis(download_url='http://intezer-download.com')

            # Act
            analysis.send(wait=True)

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISH)
        self.assertDictEqual({'analysis_id': 'asd'}, analysis.result())

    def test_send_analysis_by_file_and_get_iocs(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd',
                     status=HTTPStatus.OK,
                     json={'result': {'analysis_id': 'asd'}, 'status': 'succeeded'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd/iocs',
                     status=HTTPStatus.OK,
                     json={'result': 'ioc_report'})
            analysis = FileAnalysis(file_path='a')
            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)
                iocs = analysis.iocs

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISHED)
        self.assertEqual(iocs, 'ioc_report')

    def test_send_analysis_by_file_and_get_dynamic_ttps(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd',
                     status=HTTPStatus.OK,
                     json={'result': {'analysis_id': 'asd'}, 'status': 'succeeded'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd/dynamic-ttps',
                     status=HTTPStatus.OK,
                     json={'result': 'ttps_report'})
            analysis = FileAnalysis(file_path='a')
            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)
                ttps = analysis.dynamic_ttps

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISHED)
        self.assertEqual(ttps, 'ttps_report')

    def test_get_dynamic_ttps_raises_when_on_premise_on_21_11(self):
        # Arrange
        analysis = FileAnalysis(file_path='a')
        analysis.status = consts.AnalysisStatusCode.FINISHED
        get_global_api().on_premise_version = OnPremiseVersion.V21_11

        # Act and Assert
        with self.assertRaises(errors.UnsupportedOnPremiseVersionError):
            _ = analysis.dynamic_ttps

    def test_send_analysis_by_file_and_get_dynamic_ttps_handle_no_ttps(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd',
                     status=HTTPStatus.OK,
                     json={'result': {'analysis_id': 'asd'}, 'status': 'succeeded'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd/dynamic-ttps',
                     status=HTTPStatus.NOT_FOUND)
            analysis = FileAnalysis(file_path='a')
            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)
                self.assertIsNone(analysis.dynamic_ttps)

    def test_send_analysis_by_file_and_get_dynamic_ttps_handle_no_ttps2(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd',
                     status=HTTPStatus.OK,
                     json={'result': {'analysis_id': 'asd'}, 'status': 'succeeded'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd/dynamic-ttps',
                     status=405)
            analysis = FileAnalysis(file_path='a')
            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)
                with self.assertRaises(requests.HTTPError):
                    _ = analysis.dynamic_ttps

    def test_send_analysis_by_file_and_get_dynamic_ttps_handle_no_iocs(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd',
                     status=HTTPStatus.OK,
                     json={'result': {'analysis_id': 'asd'}, 'status': 'succeeded'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd/iocs',
                     status=405,
                     json={'result': 'ioc_report'})
            analysis = FileAnalysis(file_path='a')
            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)
                with self.assertRaises(requests.HTTPError):
                    _ = analysis.iocs

    def test_send_analysis_by_file_and_get_dynamic_ttps_handle_no_iocs2(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd',
                     status=HTTPStatus.OK,
                     json={'result': {'analysis_id': 'asd'}, 'status': 'succeeded'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd/iocs',
                     status=HTTPStatus.NOT_FOUND,
                     json={'result': 'ioc_report'})
            analysis = FileAnalysis(file_path='a')
            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)
                self.assertIsNone(analysis.iocs)

    def test_send_analysis_by_file_with_disable_unpacking(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd',
                     status=HTTPStatus.OK,
                     json={'result': {'analysis_id': 'asd'}, 'status': 'succeeded'})
            analysis = FileAnalysis(file_path='a',
                                    disable_dynamic_unpacking=True,
                                    disable_static_unpacking=True)
            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)

            # Assert
            self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISHED)
            self.assertDictEqual({'analysis_id': 'asd'}, analysis.result())
            request_body = mock.calls[0].request.body.decode()
            self.assertTrue('Content-Disposition: form-data; name="disable_static_extraction"\r\n\r\nTrue'
                            in request_body)
            self.assertTrue('Content-Disposition: form-data; name="disable_dynamic_execution"\r\n\r\nTrue'
                            in request_body)

    def test_send_analysis_by_file_with_zip_password(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd',
                     status=HTTPStatus.OK,
                     json={'result': {'analysis_id': 'asd'}, 'status': 'succeeded'})
            analysis = FileAnalysis(file_path='a',
                                    file_name='b.zip',
                                    zip_password='asd')

            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)

            # Assert
            self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISHED)
            self.assertDictEqual({'analysis_id': 'asd'}, analysis.result())
            request_body = mock.calls[0].request.body.decode()
            self.assertTrue('Content-Disposition: form-data; name="zip_password"\r\n\r\nasd'
                            in request_body)
            self.assertTrue('Content-Disposition: form-data; name="file"; filename="b.zip"'
                            in request_body)

    def test_send_analysis_by_file_with_sandbox_command_line_arguments(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd',
                     status=HTTPStatus.OK,
                     json={'result': {'analysis_id': 'asd'}, 'status': 'succeeded'})
            analysis = FileAnalysis(file_path='a',
                                    file_name='b.zip',
                                    sandbox_command_line_arguments='-c hello')

            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)

            # Assert
            self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISHED)
            self.assertDictEqual({'analysis_id': 'asd'}, analysis.result())
            request_body = mock.calls[0].request.body.decode()
            self.assertTrue('Content-Disposition: form-data; name="sandbox_command_line_arguments"\r\n\r\n-c hello'
                            in request_body)

    def test_send_analysis_by_hash_with_sandbox_command_line_arguments(self):
        # Arrange
        sha256 = 'a' * 64

        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze-by-hash',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd',
                     status=HTTPStatus.OK,
                     json={'result': {'analysis_id': 'asd'}, 'status': 'succeeded'})
            analysis = FileAnalysis(file_hash=sha256,
                                    sandbox_command_line_arguments='-c hello')

            # Act
            analysis.send(wait=True)

            # Assert
            self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISHED)
            self.assertDictEqual({'analysis_id': 'asd'}, analysis.result())
            request_body_json = json.loads(mock.calls[0].request.body)
            self.assertTrue('-c hello', request_body_json['sandbox_command_line_arguments'])

    def test_send_analysis_by_file_with_zip_password_set_filename_to_generic_one(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd',
                     status=HTTPStatus.OK,
                     json={'result': {'analysis_id': 'asd'}, 'status': 'succeeded'})
            analysis = FileAnalysis(file_stream=__file__,
                                    zip_password='asd')

            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)

            # Assert
            self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISHED)
            self.assertDictEqual({'analysis_id': 'asd'}, analysis.result())
            request_body = mock.calls[0].request.body.decode()
            self.assertTrue('Content-Disposition: form-data; name="zip_password"\r\n\r\nasd'
                            in request_body)
            self.assertTrue('Content-Disposition: form-data; name="file"; filename="file.zip"'
                            in request_body)

    def test_send_analysis_by_file_with_zip_password_adds_zip_extension(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd',
                     status=HTTPStatus.OK,
                     json={'result': {'analysis_id': 'asd'}, 'status': 'succeeded'})
            analysis = FileAnalysis(file_path='a',
                                    zip_password='asd')

            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)

            # Assert
            self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISHED)
            self.assertDictEqual({'analysis_id': 'asd'}, analysis.result())
            request_body = mock.calls[0].request.body.decode()
            self.assertTrue('Content-Disposition: form-data; name="zip_password"\r\n\r\nasd'
                            in request_body)
            self.assertTrue('Content-Disposition: form-data; name="file"; filename="a.zip"'
                            in request_body)

    def test_send_analysis_by_sha256_that_dont_exist_raise_error(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze-by-hash',
                     status=HTTPStatus.NOT_FOUND)
            analysis = FileAnalysis(file_hash='a' * 64)
            # Act + Assert
            with self.assertRaises(errors.HashDoesNotExistError):
                analysis.send()

    def test_send_analysis_by_sha256_with_expired_jwt_token_gets_new_token(self):
        # Arrange
        analysis = FileAnalysis(file_hash='a' * 64)

        # FileAnalysis attempt will initiate an access-token refresh by getting UNAUTHORIZED 401
        with responses.RequestsMock() as mock:
            def request_callback(request):
                if request.headers['Authorization'] == 'Bearer newer-access-token':
                    return HTTPStatus.CREATED, {}, json.dumps({'result_url': 'https://analyze.intezer.com/test-url'})
                if request.headers['Authorization'] == 'Bearer access-token':
                    return HTTPStatus.UNAUTHORIZED, {}, json.dumps({})
                # Fail test completley is unexpected access token received
                return HTTPStatus.SERVICE_UNAVAILABLE, {}, json.dumps({})

            mock.add_callback('POST', url=f'{self.full_url}/analyze-by-hash', callback=request_callback)
            mock.add('POST',
                     url=f'{self.full_url}/get-access-token',
                     status=HTTPStatus.OK,
                     json={'result': 'newer-access-token'})

            # Act & Assert
            analysis.send()
            self.assertEqual(3, len(mock.calls))  # analyze -> refresh access_token -> analyze retry

    def test_send_analysis_by_sha256_with_expired_jwt_token_doesnt_loop_indefinitley(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST', url=f'{self.full_url}/analyze-by-hash', status=HTTPStatus.UNAUTHORIZED)
            mock.add('POST',
                     url=f'{self.full_url}/get-access-token',
                     status=HTTPStatus.OK,
                     json={'result': 'newer-access-token'})

            analysis = FileAnalysis(file_hash='a' * 64)

            # Act & Assert
            with self.assertRaises(errors.IntezerError):
                analysis.send()

            # analyze -> get_access token -> analyze -> 401Exception
            self.assertEqual(3, len(mock.calls))

    def test_send_analysis_while_running_raise_error(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze-by-hash',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            analysis = FileAnalysis(file_hash='a' * 64)
            # Act + Assert
            with self.assertRaises(errors.AnalysisHasAlreadyBeenSentError):
                analysis.send()
                analysis.send()

    def test_send_analysis_and_get_sub_analyses(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze-by-hash',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd/sub-analyses',
                     status=HTTPStatus.OK,
                     json={'sub_analyses': [{'source': 'root', 'sub_analysis_id': 'ab', 'sha256': 'axaxaxax'},
                                            {'source': 'static_extraction', 'sub_analysis_id': 'ac', 'sha256': 'ba'}]})

            analysis = FileAnalysis(file_hash='a' * 64)

            # Act
            analysis.send()

            analysis.get_sub_analyses()

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.CREATED)
        self.assertEqual(len(analysis.get_sub_analyses()), 1)
        self.assertIsNotNone(analysis.get_root_analysis())

    def test_send_analysis_and_get_root_analyses(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze-by-hash',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd/sub-analyses',
                     status=HTTPStatus.OK,
                     json={'sub_analyses': [{'source': 'root', 'sub_analysis_id': 'ab', 'sha256': 'axaxaxax'},
                                            {'source': 'static_extraction', 'sub_analysis_id': 'ac', 'sha256': 'ba'}]})

            analysis = FileAnalysis(file_hash='a' * 64)

            # Act
            analysis.send()

            analysis.get_root_analysis()

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.CREATED)
        self.assertEqual(len(analysis.get_sub_analyses()), 1)
        self.assertIsNotNone(analysis.get_root_analysis())

    def test_send_analysis_and_sub_analyses_metadata_and_code_reuse(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze-by-hash',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd/sub-analyses',
                     status=HTTPStatus.OK,
                     json={'sub_analyses': [{'source': 'root', 'sub_analysis_id': 'ab', 'sha256': 'axaxaxax'},
                                            {'source': 'static_extraction', 'sub_analysis_id': 'ac', 'sha256': 'ba'}]})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd/sub-analyses/ab/code-reuse',
                     status=HTTPStatus.OK, json={})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd/sub-analyses/ab/metadata',
                     status=HTTPStatus.OK, json={})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd/sub-analyses/ac/code-reuse',
                     status=HTTPStatus.OK, json={})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd/sub-analyses/ac/metadata',
                     status=HTTPStatus.OK, json={})

            analysis = FileAnalysis(file_hash='a' * 64)

            # Act
            analysis.send()
            root_analysis = analysis.get_root_analysis()
            sub_analyses = analysis.get_sub_analyses()
            _ = root_analysis.code_reuse
            _ = root_analysis.metadata
            _ = sub_analyses[0].code_reuse
            _ = sub_analyses[0].metadata

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.CREATED)
        self.assertEqual(len(analysis.get_sub_analyses()), 1)
        self.assertIsNotNone(analysis.get_root_analysis())
        self.assertIsNotNone(analysis.get_root_analysis().code_reuse)
        self.assertIsNotNone(analysis.get_root_analysis().metadata)

    def test_sub_analysis_with_indicators(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze-by-hash',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd/sub-analyses',
                     status=HTTPStatus.OK,
                     json={'sub_analyses': [{'source': 'root', 'sub_analysis_id': 'ab', 'sha256': 'axaxaxax'}]})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd/sub-analyses/ab/metadata',
                     status=HTTPStatus.OK,
                     json={'indicators': [{'name': 'password_protected', 'classification': 'neutral'}]})

            analysis = FileAnalysis(file_hash='a' * 64)

            # Act
            analysis.send()
            root_analysis = analysis.get_root_analysis()
            indicators = root_analysis.indicators

        # Assert
        self.assertEqual([{'name': 'password_protected', 'classification': 'neutral'}], indicators)

    def test_sub_analysis_from_id_takes_parameters_from_composed_analysis_lazy_load_is_false(self):
        # Arrange
        analysis_id = str(uuid.uuid4())
        composed_analysis_id = str(uuid.uuid4())
        sha256 = 'axaxaxax'
        source = 'root'
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/analyses/{composed_analysis_id}/sub-analyses',
                     status=HTTPStatus.OK,
                     json={'sub_analyses': [{'source': source, 'sub_analysis_id': analysis_id, 'sha256': sha256},
                                            {'source': 'static_extraction', 'sub_analysis_id': 'ac', 'sha256': 'ba'}]})

            # Act
            sub_analysis = SubAnalysis.from_analysis_id(analysis_id, composed_analysis_id, lazy_load=False)

        # Assert
        self.assertEqual(sub_analysis.sha256, sha256)
        self.assertEqual(sub_analysis.source, source)
        self.assertIsNone(sub_analysis.extraction_info)

    def test_sub_analysis_from_id_takes_parameters_from_composed_analysis_lazy_load_is_true(self):
        # Arrange
        analysis_id = str(uuid.uuid4())
        composed_analysis_id = str(uuid.uuid4())
        sha256 = 'axaxaxax'
        source = 'root'
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/analyses/{composed_analysis_id}/sub-analyses',
                     status=HTTPStatus.OK,
                     json={'sub_analyses': [{'source': source, 'sub_analysis_id': analysis_id, 'sha256': sha256},
                                            {'source': 'static_extraction', 'sub_analysis_id': 'ac', 'sha256': 'ba'}]})

            # Act
            sub_analysis = SubAnalysis.from_analysis_id(analysis_id, composed_analysis_id)

            # Assert
            self.assertEqual(sub_analysis.sha256, sha256)
            self.assertEqual(sub_analysis.source, source)
            self.assertIsNone(sub_analysis.extraction_info)

    def test_sub_analysis_from_id_return_none_when_analysis_not_found_on_composed(self):
        # Arrange
        analysis_id = str(uuid.uuid4())
        composed_analysis_id = str(uuid.uuid4())
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/analyses/{composed_analysis_id}/sub-analyses',
                     status=HTTPStatus.OK,
                     json={'sub_analyses': []})

            # Act
            sub_analysis = SubAnalysis.from_analysis_id(analysis_id, composed_analysis_id, lazy_load=False)

        # Assert
        self.assertIsNone(sub_analysis)

    def test_sub_analysis_raises_when_getting_sha256_and_analysis_not_found_on_compose(self):
        # Arrange
        analysis_id = str(uuid.uuid4())
        composed_analysis_id = str(uuid.uuid4())
        sha256 = 'axaxaxax'
        source = 'root'
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/analyses/{composed_analysis_id}/sub-analyses',
                     status=HTTPStatus.OK,
                     json={'sub_analyses': []})

            sub_analysis = SubAnalysis.from_analysis_id(analysis_id, composed_analysis_id)
            # Act
            with self.assertRaises(errors.SubAnalysisNotFoundError):
                _ = sub_analysis.sha256

    def test_sub_analysis_operations(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyses/asd/sub-analyses/ab/code-reuse/families/ax/find-related-files',
                     status=HTTPStatus.OK,
                     json={'result_url': 'a/b/related-files'})
            mock.add('POST',
                     url=f'{self.full_url}/analyses/asd/sub-analyses/ab/get-account-related-samples',
                     status=HTTPStatus.OK,
                     json={'result_url': 'a/b/related-samples'})
            mock.add('POST',
                     url=f'{self.full_url}/analyses/asd/sub-analyses/ab/generate-vaccine',
                     status=HTTPStatus.OK,
                     json={'result_url': 'a/b/vaccine'})
            mock.add('POST',
                     url=f'{self.full_url}/analyses/asd/sub-analyses/ab/strings',
                     status=HTTPStatus.OK,
                     json={'result_url': 'a/b/strings'})
            mock.add('POST',
                     url=f'{self.full_url}/analyses/asd/sub-analyses/ab/string-related-samples',
                     status=HTTPStatus.OK,
                     json={'result_url': 'a/b/string-related-samples'})
            mock.add('POST',
                     url=f'{self.full_url}/analyses/asd/sub-analyses/ab/capabilities',
                     status=HTTPStatus.OK,
                     json={'result_url': 'a/b/capabilities'})

            mock.add('GET',
                     url=f'{self.full_url}a/b/related-files',
                     status=HTTPStatus.OK, json={'result': {'files': []}, 'status': 'succeeded'})
            mock.add('GET',
                     url=f'{self.full_url}a/b/related-samples',
                     status=HTTPStatus.OK, json={'result': {'related_samples': []}, 'status': 'succeeded'})
            mock.add('GET',
                     url=f'{self.full_url}a/b/vaccine',
                     status=HTTPStatus.OK, json={'result': 'abd', 'status': 'succeeded'})
            mock.add('GET',
                     url=f'{self.full_url}a/b/strings',
                     status=HTTPStatus.OK, json={'result': 'abd', 'status': 'succeeded'})
            mock.add('GET',
                     url=f'{self.full_url}a/b/string-related-samples',
                     status=HTTPStatus.OK, json={'result': 'abd', 'status': 'succeeded'})
            mock.add('GET',
                     url=f'{self.full_url}a/b/capabilities',
                     status=HTTPStatus.OK, json={'result': 'abd', 'status': 'succeeded'})

            sub_analysis = SubAnalysis('ab', 'asd', 'axaxax', 'root', None)

            # Act
            related_files_operation = sub_analysis.find_related_files('ax', wait=True)
            related_samples_operation = sub_analysis.get_account_related_samples(wait=True)
            vaccine_operation = sub_analysis.generate_vaccine(wait=True)
            strings_operation = sub_analysis.get_strings(wait=True)
            string_related_operation = sub_analysis.get_string_related_samples('test', wait=True)
            capabilities = sub_analysis.get_capabilities(wait=True)

        # Assert
        self.assertIsNotNone(related_files_operation.get_result())
        self.assertIsNotNone(related_samples_operation.get_result())
        self.assertIsNotNone(vaccine_operation.get_result())
        self.assertIsNotNone(strings_operation.get_result())
        self.assertIsNotNone(string_related_operation.get_result())
        self.assertIsNotNone(capabilities.get_result())

    def test_capabilities_raises_when_on_premise_21_11(self):
        # Arrange
        sub_analysis = SubAnalysis('ab', 'asd', 'axaxax', 'root', None)
        get_global_api().on_premise_version = OnPremiseVersion.V21_11

        # Act and Assert
        with self.assertRaises(errors.UnsupportedOnPremiseVersionError):
            _ = sub_analysis.get_capabilities()

    def test_send_analysis_that_running_on_server_raise_error(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze-by-hash',
                     status=409,
                     json={'result_url': 'a/sd/asd', 'result': {}})
            analysis = FileAnalysis(file_hash='a' * 64)
            # Act + Assert
            with self.assertRaises(errors.AnalysisIsAlreadyRunningError):
                analysis.send()

    def test_analysis_raise_value_error_when_no_file_option_given(self):
        # Assert
        with self.assertRaises(ValueError):
            FileAnalysis().send()

    def test_analysis_by_sha256_and_file_sent_analysis_and_raise_value_error(self):
        # Assert
        with self.assertRaises(ValueError):
            FileAnalysis(file_hash='a', file_path='/test/test')

    def test_analysis_by_sha256_raise_value_error_when_file_path_and_file_stream_given(self):
        # Assert
        with self.assertRaises(ValueError):
            FileAnalysis(file_stream=__file__, file_path='/test/test')

    def test_analysis_by_sha256_raise_value_error_when_sha256_file_path_and_file_stream_given(self):
        # Assert
        with self.assertRaises(ValueError):
            FileAnalysis(file_hash='a', file_stream=__file__, file_path='/test/test')

    def test_analysis_get_report_for_not_finish_analyze_raise_error(self):
        # Arrange
        analysis = FileAnalysis(file_hash='a')
        # Act + Assert
        with self.assertRaises(errors.ReportDoesNotExistError):
            analysis.result()

    def test_analysis_check_status_before_send_raise_error(self):
        # Arrange
        analysis = FileAnalysis(file_hash='a')

        # Act + Assert
        with self.assertRaises(errors.IntezerError):
            analysis.check_status()

    def test_analysis_check_status_after_analysis_finish_raise_error(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd',
                     status=HTTPStatus.OK,
                     json={'result': {'analysis_id': 'asd'}, 'status': 'succeeded'})
            analysis = FileAnalysis(file_path='a')

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
            mock.add('GET', url=f'{self.full_url}/files/{file_hash}', status=HTTPStatus.NOT_FOUND)

            # Act
            analysis = FileAnalysis.from_latest_hash_analysis(file_hash)

        self.assertIsNone(analysis)

    def test_get_latest_analysis_analysis_object_when_latest_analysis_found(self):
        # Arrange
        file_hash = 'hash'
        analysis_id = 'analysis_id'
        analysis_report = {'analysis_id': analysis_id}

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/files/{file_hash}',
                     status=HTTPStatus.OK,
                     json={'result': analysis_report})

            # Act
            analysis = FileAnalysis.from_latest_hash_analysis(file_hash)

        self.assertIsNotNone(analysis)
        self.assertEqual(analysis_id, analysis.analysis_id)
        self.assertEqual(consts.AnalysisStatusCode.FINISHED, analysis.status)
        self.assertDictEqual(analysis_report, analysis.result())

    def test_get_latest_analysis_analysis_object_when_latest_analysis_found_with_on_premise(self):
        # Arrange
        get_global_api().on_premise_version = OnPremiseVersion.V21_11
        file_hash = 'hash'
        analysis_id = 'analysis_id'
        analysis_report = {'analysis_id': analysis_id}

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/files/{file_hash}',
                     status=HTTPStatus.OK,
                     json={'result': analysis_report})

            # Act
            analysis = FileAnalysis.from_latest_hash_analysis(file_hash)
            self.assertEqual(mock.calls[0].request.body, b'{}')

        self.assertIsNotNone(analysis)
        self.assertEqual(analysis_id, analysis.analysis_id)
        self.assertEqual(consts.AnalysisStatusCode.FINISHED, analysis.status)
        self.assertDictEqual(analysis_report, analysis.result())

    def test_get_analysis_by_id_analysis_object_when_latest_analysis_found(self):
        # Arrange
        analysis_id = 'analysis_id'
        analysis_report = {'analysis_id': analysis_id,
                           'sha256': 'hash',
                           'analysis_time': 'Wed, 17 Oct 2018 15:16:45 GMT'}

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/analyses/{analysis_id}',
                     status=HTTPStatus.OK,
                     json={'result': analysis_report, 'status': 'succeeded'})

            # Act
            analysis = FileAnalysis.from_analysis_id(analysis_id)

        self.assertIsNotNone(analysis)
        self.assertEqual(analysis_id, analysis.analysis_id)
        self.assertEqual(consts.AnalysisStatusCode.FINISHED, analysis.status)
        self.assertDictEqual(analysis_report, analysis.result())

    def test_get_analysis_by_id_in_progress(self):
        # Arrange
        analysis_id = 'analysis_id'

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/analyses/{analysis_id}',
                     status=202,
                     json={'status': consts.AnalysisStatusCode.IN_PROGRESS.value})

            # Act
            analysis = FileAnalysis.from_analysis_id(analysis_id)
            self.assertEqual(consts.AnalysisStatusCode.IN_PROGRESS, analysis.status)
            self.assertEqual(analysis_id, analysis.analysis_id)

    def test_download_file_path_uses_content_disposition(self):
        # Arrange
        file_hash = 'hash'
        result = {'result': {'analysis_id': 'analysis_id', 'sha256': file_hash}}
        file_name = 'a.sample'

        with responses.RequestsMock() as mock:
            mock.add('GET', url=f'{self.full_url}/files/{file_hash}', status=HTTPStatus.OK, json=result)
            mock.add('GET', url=f'{self.full_url}/files/{file_hash}/download',
                     status=HTTPStatus.OK,
                     body=b'asd',
                     headers={'content-disposition': f'inline; filename={file_name}'})

            analysis = FileAnalysis.from_latest_hash_analysis(file_hash)
            with tempfile.TemporaryDirectory() as temp_dir:
                # Act
                analysis.download_file(temp_dir)

                # Assert
                files = os.listdir(temp_dir)
                self.assertEqual(file_name, files[0])

    def test_download_file_path_uses_default_file_name(self):
        # Arrange
        file_hash = 'hash'
        result = {'result': {'analysis_id': 'analysis_id', 'sha256': file_hash}}
        file_name = f'{file_hash}.sample'

        with responses.RequestsMock() as mock:
            mock.add('GET', url=f'{self.full_url}/files/{file_hash}', status=HTTPStatus.OK, json=result)
            mock.add('GET', url=f'{self.full_url}/files/{file_hash}/download', status=HTTPStatus.OK, body=b'asd')

            analysis = FileAnalysis.from_latest_hash_analysis(file_hash)
            with tempfile.TemporaryDirectory() as temp_dir:
                # Act
                analysis.download_file(temp_dir)

                # Assert
                files = os.listdir(temp_dir)
                self.assertEqual(file_name, files[0])

    def test_download_file_path(self):
        # Arrange
        file_hash = 'hash'
        result = {'result': {'analysis_id': 'analysis_id', 'sha256': file_hash}}
        content = b'asd'

        with responses.RequestsMock() as mock:
            mock.add('GET', url=f'{self.full_url}/files/{file_hash}', status=HTTPStatus.OK, json=result)
            mock.add('GET', url=f'{self.full_url}/files/{file_hash}/download', status=HTTPStatus.OK, body=content)

            analysis = FileAnalysis.from_latest_hash_analysis(file_hash)
            with tempfile.TemporaryDirectory() as temp_dir:
                file_path = os.path.join(temp_dir, f'{file_hash}.sample')

                # Act
                analysis.download_file(file_path)
                with open(file_path, 'rb') as f:
                    # Assert
                    self.assertEqual(content, f.read())

    def test_download_file_output_stream(self):
        # Arrange
        file_hash = 'hash'
        result = {'result': {'analysis_id': 'analysis_id', 'sha256': file_hash}}
        content = b'asd'

        with responses.RequestsMock() as mock:
            mock.add('GET', url=f'{self.full_url}/files/{file_hash}', status=HTTPStatus.OK, json=result)
            mock.add('GET', url=f'{self.full_url}/files/{file_hash}/download', status=HTTPStatus.OK, body=content)

            analysis = FileAnalysis.from_latest_hash_analysis(file_hash)
            output_stream = io.BytesIO()

            # Act
            analysis.download_file(output_stream=output_stream)
            output_stream.seek(0, 0)

            self.assertEqual(content, output_stream.read())

    def test_download_file_raises_when_providing_output_stream_and_path(self):
        # Arrange
        file_hash = 'hash'
        result = {'result': {'analysis_id': 'analysis_id', 'sha256': file_hash}}

        with responses.RequestsMock() as mock:
            mock.add('GET', url=f'{self.full_url}/files/{file_hash}', status=HTTPStatus.OK, json=result)

            analysis = FileAnalysis.from_latest_hash_analysis(file_hash)
            output_stream = io.BytesIO()

            # Act and Assert
            with self.assertRaises(ValueError):
                analysis.download_file(path='asd', output_stream=output_stream)

    def test_download_file_raises_when_not_providing_output_stream_and_path(self):
        # Arrange
        file_hash = 'hash'
        result = {'result': {'analysis_id': 'analysis_id', 'sha256': file_hash}}

        with responses.RequestsMock() as mock:
            mock.add('GET', url=f'{self.full_url}/files/{file_hash}', status=HTTPStatus.OK, json=result)

            analysis = FileAnalysis.from_latest_hash_analysis(file_hash)

            # Act and Assert
            with self.assertRaises(ValueError):
                analysis.download_file()

    def test_get_detection(self):
        # Arrange
        analysis = FileAnalysis(file_hash='a' * 64)
        analysis.status = consts.AnalysisStatusCode.FINISHED
        analysis_id = 'analysis_id'
        analysis.analysis_id = analysis_id
        result_url = f'{self.full_url}/analyses/{analysis_id}/detect'
        result = {
            'families': [{'family_id': 'string', 'family_name': 'string'}],
            'software_type': 'administration_tool',
            'source': 'string',
            'severity': 0,
            'type': 'string',
            'value': None
        }

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=result_url,
                     status=HTTPStatus.CREATED,
                     json={'status': consts.AnalysisStatusCode.IN_PROGRESS.value,
                           'result_url': f'/analyses/{analysis_id}/detect'})

            mock.add('GET',
                     url=f'{self.full_url}/analyses/{analysis_id}/detect',
                     status=HTTPStatus.OK,
                     json={'status': 'succeeded', 'result': [result]}
                     )

            # Act
            operation = analysis.get_detections(wait=True)

        # Assert
        self.assertEqual(operation.status, consts.AnalysisStatusCode.FINISHED)
        self.assertDictEqual(operation.result[0], result)

    def test_get_detection_return_none_when_no_report(self):
        # Arrange
        analysis = FileAnalysis(file_hash='a' * 64)
        analysis.status = consts.AnalysisStatusCode.FINISHED
        analysis_id = 'analysis_id'
        analysis.analysis_id = analysis_id

        with responses.RequestsMock() as mock:
            mock.add('GET', url=f'{self.full_url}/analyses/{analysis_id}/detect', status=HTTPStatus.CONFLICT, json={})

            # Act
            operation = analysis.get_detections(wait=True)

        # Assert
        self.assertIsNone(operation)

    def test_get_detection_raises_on_on_premise(self):
        # Arrange
        get_global_api().on_premise_version = OnPremiseVersion.V21_11
        analysis = FileAnalysis(file_hash='a' * 64)
        analysis.status = consts.AnalysisStatusCode.FINISHED
        analysis_id = 'analysis_id'
        analysis.analysis_id = analysis_id

        # Act and Assert
        with self.assertRaises(errors.UnsupportedOnPremiseVersionError):
            operation = analysis.get_detections(wait=True)

    def test_running_analysis_duration(self):
        # Arrange
        sleep = 0.1
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze-by-hash',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            analysis = FileAnalysis(file_hash='a' * 64)

            # Act
            analysis.send()

        # Assert
        time.sleep(sleep)
        self.assertGreaterEqual(analysis.running_analysis_duration, datetime.timedelta(seconds=sleep))

    def test_running_analysis_duration_returns_none_when_analysis_is_not_running(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/analyze-by-hash',
                     status=HTTPStatus.CREATED,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=f'{self.full_url}/analyses/asd',
                     status=HTTPStatus.OK,
                     json={'result': {'analysis_id': 'asd'}, 'status': 'succeeded'})
            analysis = FileAnalysis(file_hash='a' * 64)

            # Act
            analysis.send(wait=True)

        # Assert
        self.assertIsNone(analysis.running_analysis_duration)

    def test_compare_file_analysis(self):
        # Arrange
        analysis_id = 'analysis_id'
        analysis_report = {'analysis_id': analysis_id,
                           'sha256': 'hash',
                           'analysis_time': 'Wed, 17 Oct 2018 15:16:45 GMT'}

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/analyses/{analysis_id}',
                     status=HTTPStatus.OK,
                     json={'result': analysis_report, 'status': 'succeeded'})

            # Act
            analysis1 = FileAnalysis.from_analysis_id(analysis_id)
            analysis2 = FileAnalysis.from_analysis_id(analysis_id)

        # Assert
        self.assertEqual(analysis1, analysis2)
        analysis2.analysis_id = 'asd'
        self.assertNotEqual(analysis1, analysis2)

    def test_compare_returns_false_when_analysis_not_the_same_type(self):
        # Arrange
        analysis_id = str(uuid.uuid4())
        endpoint_result = {
            'status': 'succeeded',
            'result': {
                'analysis_id': analysis_id,
                'scan_status': 'done'
            }
        }
        file_report = {'analysis_id': analysis_id,
                           'sha256': 'hash',
                           'analysis_time': 'Wed, 17 Oct 2018 15:16:45 GMT'}

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/endpoint-analyses/{analysis_id}',
                     status=HTTPStatus.OK,
                     json=endpoint_result)
            mock.add('GET',
                     url=f'{self.full_url}/analyses/{analysis_id}',
                     status=HTTPStatus.OK,
                     json={'result': file_report, 'status': 'succeeded'})

            # Act
            endpoint_analysis = EndpointAnalysis.from_analysis_id(analysis_id)
            file_analysis = FileAnalysis.from_analysis_id(analysis_id)

        # Assert
        self.assertNotEqual(endpoint_analysis,file_analysis)



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
                'scan_status': 'done'
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
