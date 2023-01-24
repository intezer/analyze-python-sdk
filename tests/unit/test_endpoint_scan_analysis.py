import os.path

import responses

from intezer_sdk import consts
from intezer_sdk.endpoint_analysis import EndpointAnalysis
from tests.unit.base_test import BaseTest


class TestEndpointAnalysis(BaseTest):

    def setUp(self):
        super().setUp()

    def test_paths_initialization(self):
        metadata_dir = 'path/to/metadata'
        files_dir = 'path/to/files'
        fileless_dir = 'path/to/fileless'
        memory_modules_dir = 'path/to/memory_modules'
        analysis = EndpointAnalysis(metadata_dir=metadata_dir)
        self.assertEqual(os.path.normpath(analysis._metadata_dir), metadata_dir)
        self.assertEqual(os.path.normpath(analysis._files_dir), files_dir)
        self.assertEqual(os.path.normpath(analysis._fileless_dir), fileless_dir)
        self.assertEqual(os.path.normpath(analysis._memory_modules_dir), memory_modules_dir)

    def test_send_analyze_to_api(self):
        # Arrange
        metadata_dir = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                     '..',
                                                     'resources',
                                                     'offline_endpoint_scan',
                                                     'metadata_dir'))
        analysis = EndpointAnalysis(metadata_dir=metadata_dir)

        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=consts.BASE_API_URL + 'scans',
                     status=201,
                     json={'result': {'scan_id': '1234', 'analysis_id': '5678'}})
            mock.add('POST',
                     url=consts.ANALYZE_URL + '/scans/scans/1234/host-info',
                     status=200,
                     json={'result': {'status': 'success'}})
            mock.add('POST',
                     url=consts.ANALYZE_URL + '/scans/scans/1234/scheduled-tasks-info',
                     status=200,
                     json={'result': {'status': 'success'}})
            mock.add('POST',
                     url=consts.ANALYZE_URL + '/scans/scans/1234/processes-info',
                     status=200,
                     json={'result': {'status': 'success'}})
            mock.add('POST',
                     url=consts.ANALYZE_URL + '/scans/scans/1234/injected-modules-info',
                     status=200,
                     json={'result': {'status': 'success'}})
            mock.add('POST',
                     url=consts.ANALYZE_URL + '/scans/scans/1234/file-module-differences',
                     status=200,
                     json={'result': {'status': 'success'}})
            mock.add('POST',
                     url=consts.ANALYZE_URL + '/scans/scans/1234/processes/30056/loaded-modules-info',
                     status=200,
                     json={'result': {'status': 'success'}})
            mock.add('POST',
                     url=consts.ANALYZE_URL + '/scans/scans/1234/files-info',
                     status=200,
                     json={'result': ['53409f8b481e533d3ac74a0e64257ea16952d2c6956c8d78c1779a8223ca431e']})
            mock.add('POST',
                     url=consts.ANALYZE_URL + '/scans/scans/1234/file-system/collected-binaries',
                     status=200,
                     json={'result': {'status': 'success'}})
            mock.add('POST',
                     url=consts.ANALYZE_URL + '/scans/scans/1234/memory-module-dumps-info',
                     status=200,
                     json={'result': ['525d917ead5af7076f6c650825ba34a1dd87cb6c27d5858941a5e8a64aaaf185']})
            mock.add('POST',
                     url=consts.ANALYZE_URL + '/scans/scans/1234/memory/collected-binaries',
                     status=200,
                     json={'result': {'status': 'success'}})
            mock.add('POST',
                     url=consts.ANALYZE_URL + '/scans/scans/1234/end',
                     status=200,
                     json={'result': {'status': 'success'}})

            # Act
            analysis.send()

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.CREATED)

    def test_send_analyze_to_api_missing_files(self):
        # Arrange
        metadata_dir = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                     '..',
                                                     'resources',
                                                     'offline_endpoint_scan',
                                                     'metadata_dir_missing_files'))
        analysis = EndpointAnalysis(metadata_dir=metadata_dir)

        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=consts.BASE_API_URL + 'scans',
                     status=201,
                     json={'result': {'scan_id': '1234', 'analysis_id': '5678'}})
            mock.add('POST',
                     url=consts.ANALYZE_URL + '/scans/scans/1234/host-info',
                     status=200,
                     json={'result': {'status': 'success'}})
            mock.add('POST',
                     url=consts.ANALYZE_URL + '/scans/scans/1234/end',
                     status=200,
                     json={'result': {'status': 'failed'}})

            # Act
            try:
                analysis.send()
            except Exception as e:
                # Assert
                self.assertEqual(str(e),
                                 (
                                     '[Errno 2] No such file or directory: '
                                     ''"'/home/itamar/work/analyze-python-sdk/tests/resources/"
                                     "offline_endpoint_scan/metadata_dir_missing_files/processes_info.json'"))

        self.assertEqual(analysis.status, consts.AnalysisStatusCode.FAILED)

    def test_send_analyze_to_api_no_scheduled_tasks_info(self):
        # Arrange
        metadata_dir = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                     '..',
                                                     'resources',
                                                     'offline_endpoint_scan',
                                                     'metadata_dir_no_scheduled_tasks'))
        analysis = EndpointAnalysis(metadata_dir=metadata_dir)

        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=consts.BASE_API_URL + 'scans',
                     status=201,
                     json={'result': {'scan_id': '1234', 'analysis_id': '5678'}})
            mock.add('POST',
                     url=consts.ANALYZE_URL + '/scans/scans/1234/host-info',
                     status=200,
                     json={'result': {'status': 'success'}})
            mock.add('POST',
                     url=consts.ANALYZE_URL + '/scans/scans/1234/processes-info',
                     status=200,
                     json={'result': {'status': 'success'}})
            mock.add('POST',
                     url=consts.ANALYZE_URL + '/scans/scans/1234/injected-modules-info',
                     status=200,
                     json={'result': {'status': 'success'}})
            mock.add('POST',
                     url=consts.ANALYZE_URL + '/scans/scans/1234/file-module-differences',
                     status=200,
                     json={'result': {'status': 'success'}})
            mock.add('POST',
                     url=consts.ANALYZE_URL + '/scans/scans/1234/processes/30056/loaded-modules-info',
                     status=200,
                     json={'result': {'status': 'success'}})
            mock.add('POST',
                     url=consts.ANALYZE_URL + '/scans/scans/1234/files-info',
                     status=200,
                     json={'result': ['53409f8b481e533d3ac74a0e64257ea16952d2c6956c8d78c1779a8223ca431e']})
            mock.add('POST',
                     url=consts.ANALYZE_URL + '/scans/scans/1234/file-system/collected-binaries',
                     status=200,
                     json={'result': {'status': 'success'}})
            mock.add('POST',
                     url=consts.ANALYZE_URL + '/scans/scans/1234/memory-module-dumps-info',
                     status=200,
                     json={'result': ['525d917ead5af7076f6c650825ba34a1dd87cb6c27d5858941a5e8a64aaaf185']})
            mock.add('POST',
                     url=consts.ANALYZE_URL + '/scans/scans/1234/memory/collected-binaries',
                     status=200,
                     json={'result': {'status': 'success'}})
            mock.add('POST',
                     url=consts.ANALYZE_URL + '/scans/scans/1234/end',
                     status=200,
                     json={'result': {'status': 'success'}})

            # Act
            analysis.send()

        # Assert
        self.assertEqual(analysis.status, consts.AnalysisStatusCode.CREATED)