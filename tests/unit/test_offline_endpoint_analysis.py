import os.path
import uuid
from http import HTTPStatus

import responses

from intezer_sdk import consts
from intezer_sdk.endpoint_analysis import EndpointAnalysis
from intezer_sdk.errors import IntezerError
from tests.unit.base_test import BaseTest


class TestEndpointAnalysis(BaseTest):

    def setUp(self):
        super().setUp()

    def test_paths_initialization(self):
        # Arrange
        offline_scan_directory = os.path.join('path', 'to', 'offline_scan_directory')
        files_dir = os.path.join('path', 'to', 'files')
        fileless_dir = os.path.join('path', 'to', 'fileless')
        memory_modules_dir = os.path.join('path', 'to', 'memory_modules')

        # Act
        analysis = EndpointAnalysis(offline_scan_directory=offline_scan_directory)

        # Assert
        self.assertEqual(offline_scan_directory, os.path.normpath(analysis._offline_scan_directory))
        self.assertEqual(files_dir, os.path.normpath(analysis._files_dir))
        self.assertEqual(fileless_dir, os.path.normpath(analysis._fileless_dir))
        self.assertEqual(memory_modules_dir, os.path.normpath(analysis._memory_modules_dir))

    def test_send_analyze_to_api(self):
        # Arrange
        scan_id = str(uuid.uuid4())
        analysis_id = str(uuid.uuid4())
        offline_scan_directory = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                               '..',
                                                               'resources',
                                                               'offline_endpoint_scan',
                                                               'offline_scan_directory'))
        analysis = EndpointAnalysis(offline_scan_directory=offline_scan_directory)

        # Arrange
        with responses.RequestsMock() as mock:

            self.add_mock_requests_without_scheduled_tasks(mock, scan_id, analysis_id)
            mock.add('POST',
                     url=f'{consts.ANALYZE_URL}/scans/scans/{scan_id}/scheduled-tasks-info',
                     status=HTTPStatus.OK,
                     json={'result': {'status': 'success'}})
            # Act
            analysis.send()

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.CREATED)

        # Act 2
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{consts.BASE_URL}{consts.API_VERSION}/endpoint-analyses/{analysis_id}',
                     status=HTTPStatus.ACCEPTED,
                     json={'result': {'status': 'in_progress'}})
            analysis.check_status()

        # Assert 2
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.IN_PROGRESS)

    def test_send_analyze_to_api_missing_files(self):
        # Arrange
        scan_id = str(uuid.uuid4())
        analysis_id = str(uuid.uuid4())
        offline_scan_directory = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                               '..',
                                                               'resources',
                                                               'offline_endpoint_scan',
                                                               'offline_scan_directory_missing_files'))
        analysis = EndpointAnalysis(offline_scan_directory=offline_scan_directory)

        with responses.RequestsMock() as mock:

            mock.add('POST',
                     url=consts.BASE_URL + 'scans',
                     status=HTTPStatus.CREATED,
                     json={'result': {'scan_id': scan_id, 'analysis_id': analysis_id}})
            mock.add('POST',
                     url=f'{consts.ANALYZE_URL}/scans/scans/{scan_id}/host-info',
                     status=HTTPStatus.OK,
                     json={'result': {'status': 'success'}})
            mock.add('POST',
                     url=f'{consts.ANALYZE_URL}/scans/scans/{scan_id}/end',
                     status=HTTPStatus.OK,
                     json={'result': {'status': 'failed'}})

            # Act
            with self.assertRaises(FileNotFoundError):
                analysis.send()

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.FAILED)

    def test_send_analyze_to_api_no_scheduled_tasks_info(self):
        # Arrange
        scan_id = str(uuid.uuid4())
        analysis_id = str(uuid.uuid4())
        offline_scan_directory = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                               '..',
                                                               'resources',
                                                               'offline_endpoint_scan',
                                                               'offline_scan_directory_no_scheduled_tasks'))
        analysis = EndpointAnalysis(offline_scan_directory=offline_scan_directory)

        # Arrange
        with responses.RequestsMock() as mock:

            self.add_mock_requests_without_scheduled_tasks(mock, scan_id, analysis_id)

            # Act
            analysis.send()

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.CREATED)

    @staticmethod
    def add_mock_requests_without_scheduled_tasks(mock: responses.RequestsMock, scan_id: str, analysis_id: str):
        mock.add('POST',
                 url=consts.BASE_URL + 'scans',
                 status=HTTPStatus.CREATED,
                 json={'result': {'scan_id': scan_id, 'analysis_id': analysis_id}})
        mock.add('POST',
                 url=f'{consts.ANALYZE_URL}/scans/scans/{scan_id}/host-info',
                 status=HTTPStatus.OK,
                 json={'result': {'status': 'success'}})
        mock.add('POST',
                 url=f'{consts.ANALYZE_URL}/scans/scans/{scan_id}/processes-info',
                 status=HTTPStatus.OK,
                 json={'result': {'status': 'success'}})
        mock.add('POST',
                 url=f'{consts.ANALYZE_URL}/scans/scans/{scan_id}/injected-modules-info',
                 status=HTTPStatus.OK,
                 json={'result': {'status': 'success'}})
        mock.add('POST',
                 url=f'{consts.ANALYZE_URL}/scans/scans/{scan_id}/file-module-differences',
                 status=HTTPStatus.OK,
                 json={'result': {'status': 'success'}})
        mock.add('POST',
                 url=f'{consts.ANALYZE_URL}/scans/scans/{scan_id}/processes/30056/loaded-modules-info',
                 status=HTTPStatus.OK,
                 json={'result': {'status': 'success'}})
        mock.add('POST',
                 url=f'{consts.ANALYZE_URL}/scans/scans/{scan_id}/files-info',
                 status=HTTPStatus.OK,
                 json={'result': ['53409f8b481e533d3ac74a0e64257ea16952d2c6956c8d78c1779a8223ca431e']})
        mock.add('POST',
                 url=f'{consts.ANALYZE_URL}/scans/scans/{scan_id}/file-system/collected-binaries',
                 status=HTTPStatus.OK,
                 json={'result': {'status': 'success'}})
        mock.add('POST',
                 url=f'{consts.ANALYZE_URL}/scans/scans/{scan_id}/memory-module-dumps-info',
                 status=HTTPStatus.OK,
                 json={'result': ['525d917ead5af7076f6c650825ba34a1dd87cb6c27d5858941a5e8a64aaaf185']})
        mock.add('POST',
                 url=f'{consts.ANALYZE_URL}/scans/scans/{scan_id}/memory/collected-binaries',
                 status=HTTPStatus.OK,
                 json={'result': {'status': 'success'}})
        mock.add('POST',
                 url=f'{consts.ANALYZE_URL}/scans/scans/{scan_id}/end',
                 status=HTTPStatus.OK,
                 json={'result': {'status': 'success'}})
