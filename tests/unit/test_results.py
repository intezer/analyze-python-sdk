import contextlib
import datetime
import random
import uuid
from http import HTTPStatus

import responses

from intezer_sdk.analyses_history import generate_analyses_history_filter
from intezer_sdk.analyses_history import FILE_ANALYSES_REQUEST
from intezer_sdk.api import get_global_api
from intezer_sdk.analyses_results import AnalysesResults
from tests.unit.base_test import BaseTest


class ResultsSpec(BaseTest):
    def setUp(self):
        super().setUp()
        self.base_filter = generate_analyses_history_filter(
            start_date=datetime.datetime.now() - datetime.timedelta(days=3),
            end_date=datetime.datetime.now()
        )
        self.normal_result = {
            'total_count': 2,
            'analyses': [{'account_id': '123'}, {'account_id': '456'}]
        }
        self.no_result = {'total_count': 0, 'analyses': []}

    @contextlib.contextmanager
    def response(self, header):
        """
        Wrap with simple mock response.
        :param header: Header for the mock response.
        """
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=HTTPStatus.OK,
                     json=header)
            yield mock

    def test_fetch_page_raises_stop_iteration_when_no_more_pages_left(self):
        """
        When got no results expect to raise StopIteration exception for stopping
        the iteration that is going on outer scope.
        """
        # Arrange
        with self.response(self.no_result):
            # Act
            results = AnalysesResults(FILE_ANALYSES_REQUEST, get_global_api(), self.base_filter)

            # Assert
            self.assertListEqual([], results.all())
            with self.assertRaises(StopIteration):
                next(iter(results))

    def test_fetch_page_happy_flow(self):
        """Check regular use for fetch page"""
        # Arrange
        with self.response(self.normal_result):
            # Act & Assert
            results = AnalysesResults(FILE_ANALYSES_REQUEST, get_global_api(), self.base_filter)
            results._fetch_page()

    def test_iterate_over_rows_and_not_pages(self):
        """Check iter gives dict and not list of dicts (row and not page)."""
        # Arrange
        with self.response(self.normal_result):
            self.base_filter['limit'] = 2
            # Act
            results = AnalysesResults(FILE_ANALYSES_REQUEST, get_global_api(), self.base_filter)
            # Assert
            self.assertEqual(dict, type(next(iter(results))))

    def test_next_page_when_end_of_list_pages_fetch_new_page(self):
        """test end of list, need to ask for new page."""
        # Arrange
        self.normal_result['total_count'] = 4
        self.base_filter['limit'] = 2
        with self.response(self.normal_result) as mock:
            self.normal_result['analyses'][0]['account_id'] = str(uuid.uuid4())
            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=HTTPStatus.OK,
                     json=self.normal_result)
            # Act
            results = AnalysesResults(FILE_ANALYSES_REQUEST, get_global_api(), self.base_filter)
            result_iter = iter(results)
            next(result_iter)
            next(result_iter)
            next(result_iter)
            # Assert
            self.assertEqual(2, len(results))

    def test_all_with_no_pages_before_fetch_new_page(self):
        """Test no pages exists, need to try fetch new page."""
        # Arrange
        with self.response(self.normal_result):
            self.base_filter['limit'] = 2
            # Act
            results = AnalysesResults(FILE_ANALYSES_REQUEST, get_global_api(), self.base_filter)
            results.all()
            # Assert
            self.assertEqual(1, len(results))

    def test_all_when_end_of_list_pages_fetch_new_page(self):
        """Test all pages exists, need to try fetch new page."""
        # Arrange
        self.normal_result['total_count'] = 4
        with self.response(self.normal_result) as mock:
            self.normal_result['analyses'][0]['account_id'] = str(uuid.uuid4())
            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=HTTPStatus.OK,
                     json=self.normal_result)

            self.base_filter['limit'] = 2
            results = AnalysesResults(
                FILE_ANALYSES_REQUEST,
                get_global_api(),
                self.base_filter
            )
            result_iter = iter(results)
            next(result_iter)
            next(result_iter)

            self.normal_result['analyses'][0]['account_id'] = str(uuid.uuid4())
            # Act
            results.all()
            # Assert
            self.assertEqual(2, len(results))
