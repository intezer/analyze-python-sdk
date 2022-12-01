import copy
import datetime
import random

import responses

from intezer_sdk.analyses_history import general_data_analyses_history
from intezer_sdk.api import get_global_api
from intezer_sdk.results import Results
from tests.unit.base_test import BaseTest

FILE_ANALYSES_REQUEST = '/analyses/history'
URL_ANALYSES_REQUEST = '/url-analyses/history'
ENDPOINT_ANALYSES_REQUEST = '/endpoint-analyses/history'


class ResultsSpec(BaseTest):
    def setUp(self):
        super().setUp()
        self.base_filter = general_data_analyses_history(
            start_date=datetime.datetime.now() - datetime.timedelta(days=3),
            end_date=datetime.datetime.now()
        )
        self.normal_result = {
            'total_count': 2,
            'analyses': [{'account_id': '123'}, {'account_id': '456'}]
        }
        self.no_result = {'total_count': 0, 'analyses': []}

    def test_fetch_page_raises_stop_iteration_when_no_more_pages_left(self):
        """
        When got no results expect to raise StopIteration exception for stopping
        the iteration that is going on outer scope.
        """
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=200,
                     json=self.no_result)
            # Act
            results = Results(FILE_ANALYSES_REQUEST, get_global_api(), self.base_filter)
            # Assert
            with self.assertRaises(StopIteration):
                results._fetch_page()

    def test_fetch_page_happy_flow(self):
        """Check regular use for fetch page"""
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=200,
                     json=self.normal_result)
            # Act & Assert
            results = Results(FILE_ANALYSES_REQUEST, get_global_api(), self.base_filter)
            results._fetch_page()

    def test_iterate_over_rows_and_not_pages(self):
        """Check iter gives dict and not list of dicts (row and not page)."""
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=200,
                     json=self.normal_result)
            # Act
            results = Results(FILE_ANALYSES_REQUEST, get_global_api(), self.base_filter)
            # Assert
            self.assertEqual(dict, type(next(iter(results))))

    def test_previous_page_from_page_zero_return_page_zero(self):
        """Test return first page if run previous page from first page."""
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=200,
                     json=self.normal_result)
            # Act
            results = Results(FILE_ANALYSES_REQUEST, get_global_api(), self.base_filter)
            results._fetch_page()
            results.previous_page()
            # Assert
            self.assertEqual(results._pages[0], results._current_page)

    def test_previous_page_happy_flow(self):
        """Test happy flow get previous page."""
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=200,
                     json=self.normal_result)
            # Act
            results = Results(FILE_ANALYSES_REQUEST, get_global_api(), self.base_filter)
            results._fetch_page()
            results._pages[0][0]['account_id'] = str(random.random())
            results._fetch_page()

            results.previous_page()
            # Assert
            self.assertEqual(results._pages[0], results._current_page)

    def test_next_page_with_no_pages_before_fetch_page(self):
        """test no pages exits expect to fetch a new page."""
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=200,
                     json=self.normal_result)
            # Act
            results = Results(FILE_ANALYSES_REQUEST, get_global_api(), self.base_filter)
            result_iter = iter(results)
            next(result_iter)
        # Assert
        self.assertEqual(1, len(results._pages))

    def test_next_page_when_end_of_list_pages_fetch_new_page(self):
        """test end of list, need to ask for new page."""
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=200,
                     json=self.normal_result)

            self.normal_result['analyses'][0]['account_id'] = str(random.random())
            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=200,
                     json=self.normal_result)
            # Act
            results = Results(FILE_ANALYSES_REQUEST, get_global_api(), self.base_filter)
            result_iter = iter(results)
            next(result_iter)
            next(result_iter)
            next(result_iter)
            # Assert
            self.assertEqual(2, len(results._pages))

    def test_all_with_no_pages_before_fetch_new_page(self):
        """Test no pages exists, need to try fetch new page."""
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=200,
                     json=self.normal_result)

            self.base_filter['limit'] = 2
            # Act
            results = Results(FILE_ANALYSES_REQUEST, get_global_api(), self.base_filter)
            results.all()
            # Assert
            self.assertEqual(1, len(results._pages))

    def test_all_when_end_of_list_pages_fetch_new_page(self):
        """Test all pages exists, need to try fetch new page."""
        # Arrange
        with responses.RequestsMock() as mock:
            self.normal_result['total_count'] = 4
            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=200,
                     json=self.normal_result)

            self.normal_result['analyses'][0]['account_id'] = str(random.random())

            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=200,
                     json=self.normal_result)

            self.base_filter['limit'] = 2
            results = Results(FILE_ANALYSES_REQUEST, get_global_api(), self.base_filter)
            result_iter = iter(results)
            next(result_iter)
            next(result_iter)

            self.normal_result['analyses'][0]['account_id'] = str(random.random())

            # Act
            results.all()
            # Assert
            self.assertEqual(2, len(results._pages))
