from http import HTTPStatus

import responses

from intezer_sdk import errors
from intezer_sdk.api import set_global_api
from intezer_sdk.api import get_global_api
from intezer_sdk.operation import Operation
from intezer_sdk.operation import PaginatedOperation
from tests.unit.base_test import BaseTest


class OperationSpec(BaseTest):
    def setUp(self):
        super(OperationSpec, self).setUp()

        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/get-access-token',
                     status=200,
                     json={'result': 'access-token'})
            set_global_api()
            get_global_api().set_session()

    def test_get_operation_result(self):
        # Arrange
        url = '/test'
        expected = {'test': 'test'}

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     '{}/test'.format(self.full_url),
                     json={'result': expected})

            # Act
            operation = Operation(url, False)
            result = operation.get_result()

        # Assert
        self.assertEqual(result, expected)

    def test_get_operation_result_response_error(self):
        # Arrange
        url = '/test'

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     '{}/test'.format(self.full_url),
                     status=HTTPStatus.CREATED,
                     json={})

            # Act
            operation = Operation(url, False)

            # Assert
            self.assertRaises(errors.IntezerError, operation.get_result)

    def test_get_operation_result_still_running(self):
        # Arrange
        url = '/test'

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     '{}/test'.format(self.full_url),
                     status=HTTPStatus.ACCEPTED,
                     json={})

            # Act
            operation = Operation(url, False)

            # Assert
            self.assertRaises(errors.OperationStillRunning, operation.get_result)

    def test_fetch_paginated_operation_data_rows(self):
        # Arrange
        url = '/test'
        expected_2 = [{'test': 'test'}, {'test': 'test'}]
        expected_3 = [{'test': 'test'}, {'test': 'test'}, {'test': 'test'}]

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     '{}/test'.format(self.full_url),
                     json={'result': expected_2})

            # Act
            operation = PaginatedOperation(url, False)
            result = operation.fetch_next(2)

            # Assert
            self.assertEqual(result, expected_2)

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     '{}/test'.format(self.full_url),
                     json={'result': expected_3})

            # Act
            operation = PaginatedOperation(url, False)
            operation.fetch_next(4)

            # Assert
            self.assertRaises(errors.EndOfData, operation.fetch_next)

    def test_fetch_paginated_operation_data_rows_response_error(self):
        # Arrange
        url = '/test'

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     '{}/test'.format(self.full_url),
                     status=HTTPStatus.CREATED,
                     json={})

            # Act
            operation = PaginatedOperation(url, False)

            # Assert
            self.assertRaises(errors.IntezerError, operation.fetch_next)

    def test_fetch_paginated_operation_data_rows_still_running(self):
        # Arrange
        url = '/test'

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     '{}/test'.format(self.full_url),
                     status=HTTPStatus.ACCEPTED,
                     json={})

            # Act
            operation = PaginatedOperation(url, False)

            # Assert
            self.assertRaises(errors.OperationStillRunning, operation.fetch_next)
