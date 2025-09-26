import datetime
import io
from http import HTTPStatus
import json
import os
from unittest.mock import mock_open
from unittest.mock import patch

import responses

from intezer_sdk import consts
from intezer_sdk import errors
from intezer_sdk.file import File
from tests.unit.base_test import BaseTest


class FileSpec(BaseTest):
    def test_file_initialization_with_both_sha256_and_file_path_raises_value_error(self):
        # Act + Assert
        with self.assertRaises(ValueError):
            File(sha256='a', file_path='/path/to/file')

    def test_file_initialization_with_neither_sha256_nor_file_path_raises_value_error(self):
        # Act + Assert
        with self.assertRaises(ValueError):
            File()

    def test_file_initialization_with_sha256_sets_properties_correctly(self):
        # Arrange + Act
        file_obj = File(sha256='test_sha256')

        # Assert
        self.assertEqual(file_obj.sha256, 'test_sha256')
        self.assertIsNone(file_obj.file_path)

    def test_file_initialization_with_file_path_sets_properties_correctly(self):
        # Arrange + Act
        file_obj = File(file_path='/path/to/file')

        # Assert
        self.assertEqual(file_obj.file_path, '/path/to/file')
        self.assertIsNone(file_obj.sha256)

    def test_index_malicious_without_family_name_raises_value_error(self):
        # Arrange
        file_obj = File(sha256='a')

        # Act + Assert
        with self.assertRaises(ValueError):
            file_obj.index(consts.IndexType.MALICIOUS)

    def test_trusted_index_by_sha256_status_changes_to_created(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.post(
                url=f'{self.full_url}/files/a/index',
                status=HTTPStatus.CREATED,
                json={'result_url': '/files/index/testindex'})
            file_obj = File(sha256='a')

            # Act
            file_obj.index(consts.IndexType.TRUSTED)

        # Assert
        self.assertEqual(file_obj.index_status, consts.IndexStatusCode.CREATED)
        self.assertEqual(file_obj.index_id, 'testindex')

    def test_malicious_index_by_sha256_status_changes_to_created(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.post(
                url=f'{self.full_url}/files/a/index',
                status=HTTPStatus.CREATED,
                json={'result_url': '/files/index/testindex'})
            file_obj = File(sha256='a')

            # Act
            file_obj.index(consts.IndexType.MALICIOUS, family_name='WannaCry')

        # Assert
        self.assertEqual(file_obj.index_status, consts.IndexStatusCode.CREATED)

    def test_index_by_file_path_status_changes_to_created(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.post(
                url=f'{self.full_url}/files/index',
                status=HTTPStatus.CREATED,
                json={'result_url': '/files/index/testindex'})
            file_obj = File(file_path='a')

            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                file_obj.index(consts.IndexType.TRUSTED)

        # Assert
        self.assertEqual(file_obj.index_status, consts.IndexStatusCode.CREATED)

    def test_reindexing_creates_new_index_object(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.post(
                url=f'{self.full_url}/files/a/index',
                status=HTTPStatus.CREATED,
                json={'result_url': '/files/index/testindex1'})
            mock.post(
                url=f'{self.full_url}/files/a/index',
                status=HTTPStatus.CREATED,
                json={'result_url': '/files/index/testindex2'})
            file_obj = File(sha256='a')
            
            # Act
            file_obj.index(consts.IndexType.TRUSTED)
            first_index_id = file_obj.index_id
            
            # Reindex with different type
            file_obj.index(consts.IndexType.MALICIOUS, family_name='TestFamily')
            second_index_id = file_obj.index_id

            # Assert
            self.assertEqual(first_index_id, 'testindex1')
            self.assertEqual(second_index_id, 'testindex2')
            self.assertEqual(file_obj.index_status, consts.IndexStatusCode.CREATED)

    def test_failed_index_raises_index_failed_error(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.post(
                url=f'{self.full_url}/files/a/index',
                status=HTTPStatus.CREATED,
                json={'result_url': '/files/index/testindex'})
            mock.get(
                url=f'{self.full_url}/files/index/testindex',
                status=HTTPStatus.OK,
                json={'result_url': '/files/index/testindex',
                      'status': 'failed'})
            file_obj = File(sha256='a')

            # Act + Assert
            with self.assertRaises(errors.IndexFailedError):
                file_obj.index(consts.IndexType.TRUSTED, wait=True)

    def test_index_by_sha256_succeeds_status_changes_to_finished(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.post(
                url=f'{self.full_url}/files/a/index',
                status=HTTPStatus.CREATED,
                json={'result_url': '/files/index/testindex'})
            mock.get(
                url=f'{self.full_url}/files/index/testindex',
                status=HTTPStatus.ACCEPTED)
            mock.get(
                url=f'{self.full_url}/files/index/testindex',
                status=HTTPStatus.OK,
                json={'result_url': '/files/index/testindex',
                      'status': 'succeeded'})
            file_obj = File(sha256='a')

            # Act
            file_obj.index(consts.IndexType.TRUSTED, wait=True)

        # Assert
        self.assertEqual(file_obj.index_status, consts.IndexStatusCode.FINISHED)

    def test_index_waits_specific_time_until_completion(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.post(
                url=f'{self.full_url}/files/a/index',
                status=HTTPStatus.CREATED,
                json={'result_url': '/files/index/testindex'})
            mock.get(
                url=f'{self.full_url}/files/index/testindex',
                status=HTTPStatus.OK,
                json={'result_url': '/files/index/testindex',
                      'status': 'succeeded'})
            file_obj = File(sha256='a')
            wait = 1

            # Act
            start = datetime.datetime.utcnow()
            file_obj.index(consts.IndexType.TRUSTED, wait=1)
            duration = (datetime.datetime.utcnow() - start).total_seconds()

        # Assert
        self.assertEqual(file_obj.index_status, consts.IndexStatusCode.FINISHED)
        self.assertGreater(duration, wait)

    def test_check_index_status_before_index_sent_raises_error(self):
        # Arrange
        file_obj = File(sha256='a')

        # Act + Assert
        with self.assertRaises(ValueError):
            file_obj.check_index_status()

    def test_unset_indexing_for_sha256_file_succeeds(self):
        # Arrange
        sha256 = 'a'
        file_obj = File(sha256=sha256)
        with responses.RequestsMock() as mock:
            mock.delete(
                url=f'{self.full_url}/files/{sha256}/index',
                status=HTTPStatus.OK)
            
            # Act
            file_obj.unset_indexing()

    def test_unset_indexing_for_file_path_raises_value_error(self):
        # Arrange
        file_obj = File(file_path='/path/to/file')

        # Act + Assert
        with self.assertRaises(ValueError):
            file_obj.unset_indexing()

    def test_download_for_sha256_file_succeeds(self):
        # Arrange
        sha256 = 'a'
        file_obj = File(sha256=sha256)
        output_stream = io.BytesIO()

        with responses.RequestsMock() as mock:
            mock.get(
                url=f'{self.full_url}/files/{sha256}/download',
                status=HTTPStatus.OK,
                body=b'file_content')

            # Act
            file_obj.download(output_stream=output_stream)

        # Assert
        output_stream.seek(0)
        self.assertEqual(output_stream.read(), b'file_content')

    def test_download_for_file_path_raises_value_error(self):
        # Arrange
        file_obj = File(file_path='/path/to/file')

        # Act + Assert
        with self.assertRaises(ValueError):
            file_obj.download(output_stream=io.BytesIO())

    def test_download_with_password_protection_to_path_succeeds(self):
        # Arrange
        sha256 = 'a'
        file_obj = File(sha256=sha256)

        with responses.RequestsMock() as mock:
            mock.get(
                url=f'{self.full_url}/files/{sha256}/download',
                status=HTTPStatus.OK,
                body=b'zip_file_content')

            with patch(self.patch_prop, mock_open()) as mock_file:
                # Act
                file_obj.download(path='/tmp', password_protection='password123')

                # Assert
                mock_file.assert_called_once()
                mock_file().write.assert_called_with(b'zip_file_content')

    def test_download_to_path_succeeds(self):
        # Arrange
        sha256 = 'a'
        file_obj = File(sha256=sha256)

        with responses.RequestsMock() as mock:
            mock.get(
                url=f'{self.full_url}/files/{sha256}/download',
                status=HTTPStatus.OK,
                body=b'file_content',
                headers={'content-disposition': 'attachment; filename=test.exe'})

            with patch(self.patch_prop, mock_open()) as mock_file:
                # Act
                file_obj.download(path='/tmp')

                # Assert
                mock_file.assert_called_once()
                mock_file().write.assert_called_with(b'file_content')
    
    def test_code_reuse_by_block(self):
        TEST_HASH = "73c677dd3b264e7eb80e26e78ac9df1dba30915b5ce3b1bc1c83db52b9c6b30e"
        
        def load_response_json(file_name: str) -> dict:
            path_to_file = os.path.join(os.path.dirname(__file__), "..", "resources", file_name)
            with open(path_to_file, 'rb') as file:
                return json.load(file)
    
        with responses.RequestsMock() as mock:
            mock.add("POST",
                     url=consts.ANALYZE_URL +
                     f'/api/v2-0/files/{TEST_HASH}/code-reuse-by-code-block',
                     status=HTTPStatus.OK,
                     json=load_response_json("code_reuse_block_response.json"))
            mock.add("GET",
                     url=consts.ANALYZE_URL +
                     "/api/v2-0/analyses/51ea282b-0542-4578-a44a-e60fdfb0d3ec/code-reuse-by-code-block",
                     status=HTTPStatus.OK,
                     json=load_response_json("code_reuse_block_report.json"))

            file_object = File(sha256=TEST_HASH)
            report = file_object.get_code_blocks()

            self.assertEqual(len(report), 2527)
            self.assertEqual(
                len(list(filter(lambda x: x.is_common, report))), 1371)
            self.assertEqual(
                len(list(filter(lambda x: x.software_type == "malware", report))), 171)
