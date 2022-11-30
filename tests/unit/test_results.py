import copy
import datetime
import random

import responses

from intezer_sdk.analyses_history import AnalysesHistory
from intezer_sdk.api import get_global_api
from intezer_sdk.results import Results
from tests.unit.base_test import BaseTest

BASE_DATA = AnalysesHistory._data_analyses_history(
    start_date=datetime.datetime.now() - datetime.timedelta(days=3),
    end_date=datetime.datetime.now()
)

NO_RESULTS = {'total_count': 0, 'analyses': []}
NORMAL_RESULT = {
    'total_count': 2,
    'analyses': [{'account_id': '123'}, {'account_id': '456'}]
}

FILE_ANALYSES_REQUEST = '/analyses/history'
URL_ANALYSES_REQUEST = '/url-analyses/history'
ENDPOINT_ANALYSES_REQUEST = '/endpoint-analyses/history'


class ResultsSpec(BaseTest):
    def test_fetch_page_no_result(self):
        """
        When got no results expect to raise StopIteration exception for stopping
        the iteration that is going on outer scope.
        """
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=200,
                     json=NO_RESULTS)
            results = Results(FILE_ANALYSES_REQUEST, get_global_api(), BASE_DATA)

            with self.assertRaises(StopIteration):
                results._fetch_page()

    def test_fetch_page_happy_flow(self):
        """Check regular use for fetch page"""
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=200,
                     json=NORMAL_RESULT)

            results = Results(FILE_ANALYSES_REQUEST, get_global_api(), BASE_DATA)
            results._fetch_page()

    def test_iter_over_rows_and_not_pages(self):
        """Check iter gives dict and not list of dicts (row and not page)."""
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=200,
                     json=NORMAL_RESULT)

            results = Results(FILE_ANALYSES_REQUEST, get_global_api(), BASE_DATA)
            self.assertEqual(dict, type(next(iter(results))))

    def test_previous_page_from_page_zero(self):
        """Test return first page if run previous page from first page."""
        # HappyFLow
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=200,
                     json=NORMAL_RESULT)

            results = Results(FILE_ANALYSES_REQUEST, get_global_api(), BASE_DATA)
            results._fetch_page()
            results.previous_page()
            self.assertEqual(results.pages[0], results._current_page)

    def test_previous_page_happy_flow(self):
        """Test happy flow get previous page."""
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=200,
                     json=NORMAL_RESULT)

            results = Results(FILE_ANALYSES_REQUEST, get_global_api(), BASE_DATA)
            results._fetch_page()
            results.pages[0][0]['account_id'] = str(random.random())
            results._fetch_page()

            results.previous_page()
            self.assertEqual(results.pages[0], results._current_page)

    def test_next_page_with_no_pages_before(self):
        """test no pages exits expect to fetch a new page."""
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=200,
                     json=NORMAL_RESULT)

            results = Results(FILE_ANALYSES_REQUEST, get_global_api(), BASE_DATA)
            result_iter = iter(results)
            next(result_iter)
        self.assertEqual(1, len(results.pages))

    def test_next_page_when_end_of_list_pages(self):
        """test end of list, need to ask for new page."""
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=200,
                     json=NORMAL_RESULT)

            other_response = copy.deepcopy(NORMAL_RESULT)
            other_response['analyses'][0]['account_id'] = str(random.random())
            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=200,
                     json=other_response)

            results = Results(FILE_ANALYSES_REQUEST, get_global_api(), BASE_DATA)
            result_iter = iter(results)
            next(result_iter)
            next(result_iter)
            next(result_iter)
            self.assertEqual(2, len(results.pages))

    def test_all_with_no_pages_before(self):
        """Test no pages exists, need to try fetch new page."""
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=200,
                     json=NORMAL_RESULT)

            BASE_DATA['limit'] = 2
            results = Results(FILE_ANALYSES_REQUEST, get_global_api(), BASE_DATA)
            results.all()
            self.assertEqual(1, len(results.pages))

    def test_all_when_end_of_list_pages(self):
        """Test all pages exists, need to try fetch new page."""
        with responses.RequestsMock() as mock:
            other_response = copy.deepcopy(NORMAL_RESULT)
            other_response['total_count'] = 4
            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=200,
                     json=other_response)

            other_response['analyses'][0]['account_id'] = str(random.random())

            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=200,
                     json=other_response)

            BASE_DATA['limit'] = 2
            results = Results(FILE_ANALYSES_REQUEST, get_global_api(), BASE_DATA)
            result_iter = iter(results)
            next(result_iter)
            next(result_iter)

            NORMAL_RESULT['analyses'][0]['account_id'] = str(random.random())

            results.all()
            self.assertEqual(2, len(results.pages))
