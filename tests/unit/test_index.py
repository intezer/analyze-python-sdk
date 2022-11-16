import datetime
from unittest.mock import mock_open
from unittest.mock import patch

import responses

from intezer_sdk import consts
from intezer_sdk import errors
from intezer_sdk.index import Index
from tests.unit.base_test import BaseTest


class IndexSpec(BaseTest):
    def test_index_malicious_without_family_name_raise_value_error(self):
        # Act + Assert
        with self.assertRaises(ValueError):
            Index(sha256='a', index_as=consts.IndexType.MALICIOUS)

    def test_trusted_index_by_sha256_status_change_to_created(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/files/{}/index'.format('a'),
                     status=201,
                     json={'result_url': '/files/index/testindex'})
            index = Index(sha256='a', index_as=consts.IndexType.TRUSTED)

            # Act
            index.send()

        # Assert
        self.assertEqual(index.status, consts.IndexStatusCode.CREATED)

    def test_failed_index_raise_index_failed(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/files/{}/index'.format('a'),
                     status=201,
                     json={'result_url': '/files/index/testindex'})
            mock.add('GET',
                     url=self.full_url + '/files/index/testindex',
                     status=200,
                     json={'result_url': '/files/index/testindex',
                           'status': 'failed'})
            index = Index(sha256='a', index_as=consts.IndexType.TRUSTED)

            # Act + Assert
            with self.assertRaises(errors.IndexFailedError):
                index.send(wait=True)

    def test_malicious_index_by_sha256_status_change_to_created(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/files/{}/index'.format('a'),
                     status=201,
                     json={'result_url': '/files/index/testindex'})
            index = Index(sha256='a', index_as=consts.IndexType.MALICIOUS, family_name='WannaCry')

            # Act
            index.send()

        # Assert
        self.assertEqual(index.status, consts.IndexStatusCode.CREATED)

    def test_index_by_sha256_raise_sha256_do_not_exist(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/files/{}/index'.format('a'),
                     status=404)
            index = Index(sha256='a', index_as=consts.IndexType.TRUSTED)

            # Act + Assert
            with self.assertRaises(errors.HashDoesNotExistError):
                index.send(wait=True)

    def test_send_index_by_file_status_changed_to_created(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/files/index',
                     status=201,
                     json={'result_url': '/files/index/testindex'})
            index = Index(file_path='a', index_as=consts.IndexType.TRUSTED)

            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                index.send()

        # Assert
        self.assertEqual(index.status, consts.IndexStatusCode.CREATED)

    def test_index_by_sha256_succeeded_status_changed_to_finish(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/files/{}/index'.format('a'),
                     status=201,
                     json={'result_url': '/files/index/testindex'})
            mock.add('GET',
                     url=self.full_url + '/files/index/testindex',
                     status=202)
            mock.add('GET',
                     url=self.full_url + '/files/index/testindex',
                     status=202)
            mock.add('GET',
                     url=self.full_url + '/files/index/testindex',
                     status=200,
                     json={'result_url': '/files/index/testindex',
                           'status': 'succeeded'})
            index = Index(sha256='a', index_as=consts.IndexType.TRUSTED)

            # Act
            index.send(wait=True)

        # Assert
        self.assertEqual(index.status, consts.IndexStatusCode.FINISHED)

    def test_index_by_sha256_waits_specific_time_until_compilation(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/files/{}/index'.format('a'),
                     status=201,
                     json={'result_url': '/files/index/testindex'})
            mock.add('GET',
                     url=self.full_url + '/files/index/testindex',
                     status=200,
                     json={'result_url': '/files/index/testindex',
                           'status': 'succeeded'})
            index = Index(sha256='a', index_as=consts.IndexType.TRUSTED)
            wait = 1
            # Act
            start = datetime.datetime.utcnow()
            index.send(wait=1)
            duration = (datetime.datetime.utcnow() - start).total_seconds()

        # Assert
        self.assertEqual(index.status, consts.IndexStatusCode.FINISHED)
        self.assertGreater(duration, wait)

    def test_index_by_file_succeeded_status_changed_to_finish(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/files/index',
                     status=201,
                     json={'result_url': '/files/index/testindex'})
            mock.add('GET',
                     url=self.full_url + '/files/index/testindex',
                     status=202)
            mock.add('GET',
                     url=self.full_url + '/files/index/testindex',
                     status=202)
            mock.add('GET',
                     url=self.full_url + '/files/index/testindex',
                     status=200,
                     json={'result_url': '/files/index/testindex',
                           'status': 'succeeded'})
            index = Index(file_path='a', index_as=consts.IndexType.TRUSTED)

            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                index.send(wait=True)

        # Assert
        self.assertEqual(index.status, consts.IndexStatusCode.FINISHED)

    def test_check_status_before_index_sent_raise_status(self):
        # Arrange
        index = Index(sha256='a', index_as=consts.IndexType.TRUSTED)

        # Act + Assert
        with self.assertRaises(errors.IntezerError):
            index.check_status()

    def test_send_index_by_file_with_pulling_and_get_status_finish(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/files/index',
                     status=201,
                     json={'result_url': '/files/index/testindex'})
            mock.add('GET',
                     url=self.full_url + '/files/index/testindex',
                     status=202)
            mock.add('GET',
                     url=self.full_url + '/files/index/testindex',
                     status=202)
            mock.add('GET',
                     url=self.full_url + '/files/index/testindex',
                     status=200,
                     json={'result_url': '/files/index/testindex',
                           'status': 'succeeded'})
            index = Index(file_path='a', index_as=consts.IndexType.TRUSTED)

            with patch(self.patch_prop, mock_open(read_data='data')):
                # Act
                index.send()
                index.check_status()
                index.check_status()
                index.check_status()

        # Assert
        self.assertEqual(index.status, consts.IndexStatusCode.FINISHED)

    def test_parallel_index_by_sha256_succeeded_status_changed_to_finish(self):
        # Arrange
        with responses.RequestsMock() as mock:
            first_index_name = 'a'
            second_index_name = 'b'
            mock.add('POST',
                     url=self.full_url + '/files/{}/index'.format(first_index_name),
                     status=201,
                     json={'result_url': '/files/index/first'})
            mock.add('POST',
                     url=self.full_url + '/files/{}/index'.format(second_index_name),
                     status=201,
                     json={'result_url': '/files/index/second'})
            mock.add('GET',
                     url=self.full_url + '/files/index/first',
                     status=200,
                     json={'result_url': '/files/index/testindex',
                           'status': 'succeeded'})
            mock.add('GET',
                     url=self.full_url + '/files/index/second',
                     status=200,
                     json={'result_url': '/files/index/testindex',
                           'status': 'succeeded'})
            first_index = Index(sha256=first_index_name, index_as=consts.IndexType.TRUSTED)
            second_index = Index(sha256=second_index_name, index_as=consts.IndexType.TRUSTED)

            # Act
            first_index.send()
            second_index.send()
            first_index.wait_for_completion()
            second_index.wait_for_completion()

        # Assert
        self.assertEqual(first_index.status, consts.IndexStatusCode.FINISHED)
        self.assertEqual(second_index.status, consts.IndexStatusCode.FINISHED)
