import datetime
import json
import uuid
from http import HTTPStatus
from unittest.mock import mock_open
from unittest.mock import patch

import requests
import responses

from intezer_sdk import consts
from intezer_sdk import errors
from intezer_sdk.analysis import FileAnalysis
from intezer_sdk.analysis import UrlAnalysis
from intezer_sdk.api import get_global_api
from intezer_sdk.consts import AnalysisStatusCode
from intezer_sdk.consts import OnPremiseVersion
from intezer_sdk.sub_analysis import SubAnalysis
from tests.unit.base_test import BaseTest


class FileAnalysisSpec(BaseTest):
    def test_send_analysis_by_sha256_sent_analysis_and_sets_status(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/analyze-by-hash',
                     status=201,
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
                     url=self.full_url + '/analyze',
                     status=201,
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
                     url=self.full_url + '/analyze',
                     status=201,
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
                     url=self.full_url + '/analyze',
                     status=201,
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
                     url=self.full_url + '/analyze',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=self.full_url + '/analyses/asd',
                     status=200,
                     json={'result': 'report', 'status': 'succeeded'})
            analysis = FileAnalysis(file_path='a')

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
                     json={'result': 'report', 'status': 'succeeded'})
            analysis = FileAnalysis(file_path='a')
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
                     json={'result': 'report', 'status': 'succeeded'})
            analysis = FileAnalysis(file_path='a')

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
                     json={'result': 'report', 'status': 'succeeded'})
            analysis = FileAnalysis(file_path='a')

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
                     json={'result': 'report', 'status': 'succeeded'})
            analysis = FileAnalysis(file_path='a')
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
                     json={'result': 'report', 'status': 'succeeded'})
            mock.add('GET',
                     url=self.full_url + '/analyses/asd/iocs',
                     status=200,
                     json={'result': 'ioc_report'})
            analysis = FileAnalysis(file_path='a')
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
                     json={'result': 'report', 'status': 'succeeded'})
            mock.add('GET',
                     url=self.full_url + '/analyses/asd/dynamic-ttps',
                     status=200,
                     json={'result': 'ttps_report'})
            analysis = FileAnalysis(file_path='a')
            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                analysis.send(wait=True)
                ttps = analysis.dynamic_ttps

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISH)
        self.assertEqual(ttps, 'ttps_report')

    def test_get_dynamic_ttps_raises_when_on_premise_on_21_11(self):
        # Arrange
        analysis = FileAnalysis(file_path='a')
        analysis.status = consts.AnalysisStatusCode.FINISH
        get_global_api().on_premise_version = OnPremiseVersion.V21_11

        # Act and Assert
        with self.assertRaises(errors.UnsupportedOnPremiseVersionError):
            _ = analysis.dynamic_ttps

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
                     json={'result': 'report', 'status': 'succeeded'})
            mock.add('GET',
                     url=self.full_url + '/analyses/asd/dynamic-ttps',
                     status=404)
            analysis = FileAnalysis(file_path='a')
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
                     json={'result': 'report', 'status': 'succeeded'})
            mock.add('GET',
                     url=self.full_url + '/analyses/asd/dynamic-ttps',
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
                     url=self.full_url + '/analyze',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=self.full_url + '/analyses/asd',
                     status=200,
                     json={'result': 'report', 'status': 'succeeded'})
            mock.add('GET',
                     url=self.full_url + '/analyses/asd/iocs',
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
                     url=self.full_url + '/analyze',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=self.full_url + '/analyses/asd',
                     status=200,
                     json={'result': 'report', 'status': 'succeeded'})
            mock.add('GET',
                     url=self.full_url + '/analyses/asd/iocs',
                     status=404,
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
                     url=self.full_url + '/analyze',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=self.full_url + '/analyses/asd',
                     status=200,
                     json={'result': 'report', 'status': 'succeeded'})
            analysis = FileAnalysis(file_path='a',
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
                     json={'result': 'report', 'status': 'succeeded'})
            analysis = FileAnalysis(file_path='a',
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
                     json={'result': 'report', 'status': 'succeeded'})
            analysis = FileAnalysis(file_stream=__file__,
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
                     json={'result': 'report', 'status': 'succeeded'})
            analysis = FileAnalysis(file_path='a',
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
                     url=self.full_url + '/analyze-by-hash',
                     status=201,
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
                     url=self.full_url + '/analyze-by-hash',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=self.full_url + '/analyses/asd/sub-analyses',
                     status=200,
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
                     url=self.full_url + '/analyze-by-hash',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=self.full_url + '/analyses/asd/sub-analyses',
                     status=200,
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
                     url=self.full_url + '/analyze-by-hash',
                     status=409,
                     json={'result_url': 'a/sd/asd'})
            analysis = FileAnalysis(file_hash='a' * 64)
            # Act + Assert
            with self.assertRaises(errors.AnalysisIsAlreadyRunningError):
                analysis.send()

    def test_analysis_raise_value_error_when_no_file_option_given(self):
        # Assert
        with self.assertRaises(ValueError):
            FileAnalysis()

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
                     url=self.full_url + '/analyze',
                     status=201,
                     json={'result_url': 'a/sd/asd'})
            mock.add('GET',
                     url=self.full_url + '/analyses/asd',
                     status=200,
                     json={'result': 'report', 'status': 'succeeded'})
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
            mock.add('GET', url='{}/files/{}'.format(self.full_url, file_hash), status=404)

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
                     url='{}/files/{}'.format(self.full_url, file_hash),
                     status=200,
                     json={'result': analysis_report})

            # Act
            analysis = FileAnalysis.from_latest_hash_analysis(file_hash)

        self.assertIsNotNone(analysis)
        self.assertEqual(analysis_id, analysis.analysis_id)
        self.assertEqual(consts.AnalysisStatusCode.FINISH, analysis.status)
        self.assertDictEqual(analysis_report, analysis.result())

    def test_get_latest_analysis_analysis_object_when_latest_analysis_found_with_on_premise(self):
        # Arrange
        get_global_api().on_premise_version = OnPremiseVersion.V21_11
        file_hash = 'hash'
        analysis_id = 'analysis_id'
        analysis_report = {'analysis_id': analysis_id}

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url='{}/files/{}'.format(self.full_url, file_hash),
                     status=200,
                     json={'result': analysis_report})

            # Act
            analysis = FileAnalysis.from_latest_hash_analysis(file_hash)
            self.assertEqual(mock.calls[0].request.body, b'{}')

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
            analysis = FileAnalysis.from_analysis_id(analysis_id)

        self.assertIsNotNone(analysis)
        self.assertEqual(analysis_id, analysis.analysis_id)
        self.assertEqual(consts.AnalysisStatusCode.FINISH, analysis.status)
        self.assertDictEqual(analysis_report, analysis.result())

    def test_get_analysis_by_id_raises_when_analysis_is_not_finished(self):
        # Arrange
        analysis_id = 'analysis_id'

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url='{}/analyses/{}'.format(self.full_url, analysis_id),
                     status=202,
                     json={'status': AnalysisStatusCode.IN_PROGRESS.value})

            # Act
            with self.assertRaises(errors.AnalysisIsStillRunningError):
                FileAnalysis.from_analysis_id(analysis_id)

    def test_get_analysis_by_id_raises_when_analysis_is_queued(self):
        # Arrange
        analysis_id = 'analysis_id'

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url='{}/analyses/{}'.format(self.full_url, analysis_id),
                     status=202,
                     json={'status': AnalysisStatusCode.QUEUED.value})

            # Act
            with self.assertRaises(errors.AnalysisIsStillRunningError):
                FileAnalysis.from_analysis_id(analysis_id)


class UrlAnalysisSpec(BaseTest):
    def test_get_analysis_by_id_analysis_object_when_latest_analysis_found(self):
        # Arrange
        analysis_id = 'analysis_id'
        analysis_report = {'analysis_id': analysis_id, 'submitted_url': 'https://url.com'}

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url='{}/url/{}'.format(self.full_url, analysis_id),
                     status=200,
                     json={'result': analysis_report, 'status': 'succeeded'})

            # Act
            analysis = UrlAnalysis.from_analysis_id(analysis_id)

        self.assertIsNotNone(analysis)
        self.assertEqual(analysis_id, analysis.analysis_id)
        self.assertEqual(consts.AnalysisStatusCode.FINISH, analysis.status)
        self.assertDictEqual(analysis_report, analysis.result())

    def test_get_analysis_by_id_raises_when_analysis_is_not_finished(self):
        # Arrange
        analysis_id = 'analysis_id'

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url='{}/url/{}'.format(self.full_url, analysis_id),
                     status=202,
                     json={'status': AnalysisStatusCode.IN_PROGRESS.value})

            # Act
            with self.assertRaises(errors.AnalysisIsStillRunningError):
                UrlAnalysis.from_analysis_id(analysis_id)

    def test_get_analysis_by_id_raises_when_analysis_failed(self):
        # Arrange
        analysis_id = 'analysis_id'

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url='{}/url/{}'.format(self.full_url, analysis_id),
                     status=200,
                     json={'status': AnalysisStatusCode.FAILED.value})

            # Act
            with self.assertRaises(errors.AnalysisFailedError):
                UrlAnalysis.from_analysis_id(analysis_id)

    def test_send_perform_request_and_sets_analysis_status(self):
        # Arrange
        analysis_id = str(uuid.uuid4())
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/url/',
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
                     url=self.full_url + '/url/',
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
                     url=self.full_url + '/url/',
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
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.FINISH)
        self.assertDictEqual(analysis.result(), result)

    def test_send_waits_to_compilation_when_requested_and_handles_failure(self):
        # Arrange
        analysis_id = str(uuid.uuid4())

        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/url/',
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
                     url=self.full_url + '/url/',
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
                     url=self.full_url + '/url/',
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
