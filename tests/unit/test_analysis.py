import datetime
import json
from http import HTTPStatus
from unittest.mock import mock_open
from unittest.mock import patch

import requests
import responses

from intezer_sdk import consts
from intezer_sdk import errors
from intezer_sdk.analysis import Analysis
from intezer_sdk.analysis import get_analysis_by_id
from intezer_sdk.analysis import get_latest_analysis
from intezer_sdk.api import get_global_api
from intezer_sdk.api import set_global_api
from intezer_sdk.consts import AnalysisStatusCode
from intezer_sdk.sub_analysis import SubAnalysis
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

    def test_send_analysis_by_file_sends_analysis_and_waits_specific_time_until_compilation(self):
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
            wait = 1

            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                start = datetime.datetime.utcnow()
                analysis.send(wait=wait)
                duration = (datetime.datetime.utcnow() - start).total_seconds()

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISH)
        self.assertGreater(duration, wait)

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

    def test_send_analysis_by_file_and_get_iocs(self):
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
            mock.add('GET',
                     url=self.full_url + '/analyses/asd/iocs',
                     status=200,
                     json={'result': 'ioc_report'})
            analysis = Analysis(file_path='a')
            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)
                iocs = analysis.iocs

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISH)
        self.assertEqual(iocs, 'ioc_report')

    def test_send_analysis_by_file_and_get_dynamic_ttps(self):
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
            mock.add('GET',
                     url=self.full_url + '/analyses/asd/dynamic-ttps',
                     status=200,
                     json={'result': 'ttps_report'})
            analysis = Analysis(file_path='a')
            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)
                ttps = analysis.dynamic_ttps

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISH)
        self.assertEqual(ttps, 'ttps_report')

    def test_send_analysis_by_file_and_get_dynamic_ttps_handle_no_ttps(self):
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
            mock.add('GET',
                     url=self.full_url + '/analyses/asd/dynamic-ttps',
                     status=404)
            analysis = Analysis(file_path='a')
            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)
                self.assertIsNone(analysis.dynamic_ttps)

    def test_send_analysis_by_file_and_get_dynamic_ttps_handle_no_ttps2(self):
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
            mock.add('GET',
                     url=self.full_url + '/analyses/asd/dynamic-ttps',
                     status=405)
            analysis = Analysis(file_path='a')
            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)
                with self.assertRaises(requests.HTTPError):
                    _ = analysis.dynamic_ttps


    def test_send_analysis_by_file_and_get_dynamic_ttps_handle_no_iocs(self):
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
            mock.add('GET',
                     url=self.full_url + '/analyses/asd/iocs',
                     status=405,
                     json={'result': 'ioc_report'})
            analysis = Analysis(file_path='a')
            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)
                with self.assertRaises(requests.HTTPError):
                    _ = analysis.iocs

    def test_send_analysis_by_file_and_get_dynamic_ttps_handle_no_iocs2(self):
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
            mock.add('GET',
                     url=self.full_url + '/analyses/asd/iocs',
                     status=404,
                     json={'result': 'ioc_report'})
            analysis = Analysis(file_path='a')
            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)
                self.assertIsNone(analysis.iocs)


    def test_send_analysis_by_file_with_disable_unpacking(self):
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
            analysis = Analysis(file_path='a',
                                disable_dynamic_unpacking=True,
                                disable_static_unpacking=True)
            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)

            # Assert
            self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISH)
            self.assertEqual(analysis.result(), 'report')
            request_body = mock.calls[0].request.body.decode()
            self.assertTrue('Content-Disposition: form-data; name="disable_static_extraction"\r\n\r\nTrue'
                            in request_body)
            self.assertTrue('Content-Disposition: form-data; name="disable_dynamic_execution"\r\n\r\nTrue'
                            in request_body)

    def test_send_analysis_by_file_with_zip_password(self):
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
            analysis = Analysis(file_path='a',
                                file_name='b.zip',
                                zip_password='asd')

            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)

            # Assert
            self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISH)
            self.assertEqual(analysis.result(), 'report')
            request_body = mock.calls[0].request.body.decode()
            self.assertTrue('Content-Disposition: form-data; name="zip_password"\r\n\r\nasd'
                            in request_body)
            self.assertTrue('Content-Disposition: form-data; name="file"; filename="b.zip"'
                            in request_body)

    def test_send_analysis_by_file_with_zip_password_set_filename_to_generic_one(self):
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
            analysis = Analysis(file_stream=__file__,
                                zip_password='asd')

            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)

            # Assert
            self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISH)
            self.assertEqual(analysis.result(), 'report')
            request_body = mock.calls[0].request.body.decode()
            self.assertTrue('Content-Disposition: form-data; name="zip_password"\r\n\r\nasd'
                            in request_body)
            self.assertTrue('Content-Disposition: form-data; name="file"; filename="file.zip"'
                            in request_body)

    def test_send_analysis_by_file_with_zip_password_adds_zip_extension(self):
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
            analysis = Analysis(file_path='a',
                                zip_password='asd')

            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)

            # Assert
            self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISH)
            self.assertEqual(analysis.result(), 'report')
            request_body = mock.calls[0].request.body.decode()
            self.assertTrue('Content-Disposition: form-data; name="zip_password"\r\n\r\nasd'
                            in request_body)
            self.assertTrue('Content-Disposition: form-data; name="file"; filename="a.zip"'
                            in request_body)

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

    def test_send_analysis_by_sha256_with_expired_jwt_token_gets_new_token(self):
        # Arrange
        analysis = Analysis(file_hash='a' * 64)

        # Analysis attempt will initiate an access-token refresh by getting UNAUTHORIZED 401
        with responses.RequestsMock() as mock:
            def request_callback(request):
                if request.headers['Authorization'] == 'Bearer newer-access-token':
                    return HTTPStatus.CREATED, {}, json.dumps({'result_url': 'https://analyze.intezer.com/test-url'})
                if request.headers['Authorization'] == 'Bearer access-token':
                    return HTTPStatus.UNAUTHORIZED, {}, json.dumps({})
                # Fail test completley is unexpected access token received
                return HTTPStatus.SERVICE_UNAVAILABLE, {}, json.dumps({})

            mock.add_callback('POST', url=self.full_url + '/analyze-by-hash', callback=request_callback)
            mock.add('POST',
                     url=self.full_url + '/get-access-token',
                     status=HTTPStatus.OK,
                     json={'result': 'newer-access-token'})

            # Act & Assert
            analysis.send()
            self.assertEqual(3, len(mock.calls))  # analyze -> refresh access_token -> analyze retry

    def test_send_analysis_by_sha256_with_expired_jwt_token_doesnt_loop_indefinitley(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST', url=self.full_url + '/analyze-by-hash', status=HTTPStatus.UNAUTHORIZED)
            mock.add('POST',
                     url=self.full_url + '/get-access-token',
                     status=HTTPStatus.OK,
                     json={'result': 'newer-access-token'})

            analysis = Analysis(file_hash='a' * 64)

            # Act & Assert
            with self.assertRaises(errors.IntezerError):
                analysis.send()

            # analyze -> get_access token -> analyze -> 401Exception
            self.assertEqual(3, len(mock.calls))

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

    def test_send_analysis_and_get_sub_analyses(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/analyze-by-hash',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=self.full_url + '/analyses/asd/sub-analyses',
                     status=200,
                     json={'sub_analyses': [{'source': 'root', 'sub_analysis_id': 'ab', 'sha256': 'axaxaxax'},
                                            {'source': 'static_extraction', 'sub_analysis_id': 'ac', 'sha256': 'ba'}]})

            analysis = Analysis(file_hash='a' * 64)

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
                     url=self.full_url + '/analyze-by-hash',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=self.full_url + '/analyses/asd/sub-analyses',
                     status=200,
                     json={'sub_analyses': [{'source': 'root', 'sub_analysis_id': 'ab', 'sha256': 'axaxaxax'},
                                            {'source': 'static_extraction', 'sub_analysis_id': 'ac', 'sha256': 'ba'}]})

            analysis = Analysis(file_hash='a' * 64)

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
                     url=self.full_url + '/analyze-by-hash',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=self.full_url + '/analyses/asd/sub-analyses',
                     status=200,
                     json={'sub_analyses': [{'source': 'root', 'sub_analysis_id': 'ab', 'sha256': 'axaxaxax'},
                                            {'source': 'static_extraction', 'sub_analysis_id': 'ac', 'sha256': 'ba'}]})
            mock.add('GET',
                     url=self.full_url + '/analyses/asd/sub-analyses/ab/code-reuse',
                     status=200, json={})
            mock.add('GET',
                     url=self.full_url + '/analyses/asd/sub-analyses/ab/metadata',
                     status=200, json={})
            mock.add('GET',
                     url=self.full_url + '/analyses/asd/sub-analyses/ac/code-reuse',
                     status=200, json={})
            mock.add('GET',
                     url=self.full_url + '/analyses/asd/sub-analyses/ac/metadata',
                     status=200, json={})

            analysis = Analysis(file_hash='a' * 64)

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

    def test_sub_analysis_operations(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/analyses/asd/sub-analyses/ab/code-reuse/families/ax/find-related-files',
                     status=200,
                     json={'result_url': 'a/b/related-files'})
            mock.add('POST',
                     url=self.full_url + '/analyses/asd/sub-analyses/ab/get-account-related-samples',
                     status=200,
                     json={'result_url': 'a/b/related-samples'})
            mock.add('POST',
                     url=self.full_url + '/analyses/asd/sub-analyses/ab/generate-vaccine',
                     status=200,
                     json={'result_url': 'a/b/vaccine'})
            mock.add('POST',
                     url=self.full_url + '/analyses/asd/sub-analyses/ab/strings',
                     status=200,
                     json={'result_url': 'a/b/strings'})
            mock.add('POST',
                     url=self.full_url + '/analyses/asd/sub-analyses/ab/string-related-samples',
                     status=200,
                     json={'result_url': 'a/b/string-related-samples'})
            mock.add('POST',
                     url=self.full_url + '/analyses/asd/sub-analyses/ab/capabilities',
                     status=200,
                     json={'result_url': 'a/b/capabilities'})

            mock.add('GET',
                     url=self.full_url + 'a/b/related-files',
                     status=200, json={'result': {'files': []}})
            mock.add('GET',
                     url=self.full_url + 'a/b/related-samples',
                     status=200, json={'result': {'related_samples': []}})
            mock.add('GET',
                     url=self.full_url + 'a/b/vaccine',
                     status=200, json={'result': 'abd'})
            mock.add('GET',
                     url=self.full_url + 'a/b/strings',
                     status=200, json={'result': 'abd'})
            mock.add('GET',
                     url=self.full_url + 'a/b/string-related-samples',
                     status=200, json={'result': 'abd'})
            mock.add('GET',
                     url=self.full_url + 'a/b/capabilities',
                     status=200, json={'result': 'abd'})

            sub_analysis = SubAnalysis('ab', 'asd', 'axaxax', 'root')

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

    def test_get_analysis_by_id_analysis_object_when_latest_analysis_found(self):
        # Arrange
        analysis_id = 'analysis_id'
        analysis_report = {'analysis_id': analysis_id, 'sha256': 'hash'}

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url='{}/analyses/{}'.format(self.full_url, analysis_id),
                     status=200,
                     json={'result': analysis_report, 'status': 'succeeded'})

            # Act
            analysis = get_analysis_by_id(analysis_id)

        self.assertIsNotNone(analysis)
        self.assertEqual(analysis_id, analysis.analysis_id)
        self.assertEqual(consts.AnalysisStatusCode.FINISH, analysis.status)
        self.assertDictEqual(analysis_report, analysis.result())

    def test_get_analysis_by_id_raises_when_analysis_is_not_finished(self):
        # Arrange
        analysis_id = 'analysis_id'
        analysis_report = {'analysis_id': analysis_id, 'sha256': 'hash'}

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url='{}/analyses/{}'.format(self.full_url, analysis_id),
                     status=202,
                     json={'status': AnalysisStatusCode.IN_PROGRESS.value})

            # Act
            with self.assertRaises(errors.AnalysisIsStillRunning):
                _ = get_analysis_by_id(analysis_id)

    def test_get_analysis_by_id_raises_when_analysis_is_queued(self):
        # Arrange
        analysis_id = 'analysis_id'
        analysis_report = {'analysis_id': analysis_id, 'sha256': 'hash'}

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url='{}/analyses/{}'.format(self.full_url, analysis_id),
                     status=202,
                     json={'status': AnalysisStatusCode.QUEUED.value})

            # Act
            with self.assertRaises(errors.AnalysisIsStillRunning):
                analysis = get_analysis_by_id(analysis_id)
