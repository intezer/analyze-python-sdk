import contextlib
import copy
import datetime
import uuid
from http import HTTPStatus
from typing import List

import responses

from intezer_sdk.analyses_history import ENDPOINT_ANALYSES_REQUEST
from intezer_sdk.analyses_history import URL_ANALYSES_REQUEST
from intezer_sdk.analyses_history import generate_analyses_history_filter
from intezer_sdk.analyses_history import FILE_ANALYSES_REQUEST
from intezer_sdk.analyses_history import query_endpoint_analyses_history
from intezer_sdk.analyses_history import query_file_analyses_history
from intezer_sdk.analyses_history import query_url_analyses_history
from intezer_sdk.api import get_global_api
from intezer_sdk.analyses_results import AnalysesHistoryResult
from tests.unit.base_test import BaseTest


class ResultsSpec(BaseTest):
    def setUp(self):
        super().setUp()
        self.start_date = datetime.datetime.now() - datetime.timedelta(days=3)
        self.end_date = datetime.datetime.now()
        self.base_filter = generate_analyses_history_filter(
            start_date=self.start_date, end_date=self.end_date
        )
        self.normal_result = {
            'total_count': 2,
            'analyses': [{'account_id': '123'}, {'account_id': '456'}]
        }
        self.no_result = {'total_count': 0, 'analyses': []}
        self.expected_result = copy.deepcopy(self.normal_result['analyses'])

    @contextlib.contextmanager
    def add_mock_response(self, header, request_url_path=FILE_ANALYSES_REQUEST):
        """
        Wrap with simple mock response.
        :param header: Header for the mock response.
        :param request_url_path: Url to request new filter from.
        """
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + request_url_path,
                     status=HTTPStatus.OK,
                     json=header)
            self.expected_result = copy.deepcopy(self.normal_result['analyses'])
            yield mock

    def assert_deep_lists_equal(self, lst1: List, lst2: List):
        [self.assertDictEqual(x, y) for x, y in zip(lst1, lst2)]

    def test_current_page_never_none(self):
        """Current page will always hold a page even thought didn't ask to fetch analyse yet."""
        with self.add_mock_response(self.normal_result):
            results = AnalysesHistoryResult(FILE_ANALYSES_REQUEST, get_global_api(), self.base_filter)
            self.assertIsNotNone(results.current_page())

    def test_fetch_analyses_raises_stop_iteration_when_no_more_analyses_left(self):
        """
        When got no results expect to raise StopIteration exception for stopping
        the iteration that is going on outer scope.
        """
        # Arrange
        with self.add_mock_response(self.no_result):
            # Act
            results = AnalysesHistoryResult(FILE_ANALYSES_REQUEST, get_global_api(), self.base_filter)

            # Assert
            self.assertListEqual([], results.all())
            with self.assertRaises(StopIteration):
                next(iter(results))

    def test_iterate_return_one_analyses(self):
        """Check iter yield new analyse."""
        # Arrange
        with self.add_mock_response(self.normal_result):
            self.base_filter['limit'] = 2
            # Act
            results = AnalysesHistoryResult(FILE_ANALYSES_REQUEST, get_global_api(), self.base_filter)
            # Assert
            self.assertEqual(self.expected_result[0], next(iter(results)))

    def test_next_analyses_when_fetched_analyses_before(self):
        """Test end of analyses exists, need to fetch new analyses."""
        # Arrange
        self.normal_result['total_count'] = 4
        self.base_filter['limit'] = 2
        with self.add_mock_response(self.normal_result) as mock:
            self.normal_result['analyses'][0]['account_id'] = str(uuid.uuid4())
            self.expected_result.extend(self.normal_result['analyses'].copy())
            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=HTTPStatus.OK,
                     json=self.normal_result)
            # Act
            results = AnalysesHistoryResult(FILE_ANALYSES_REQUEST, get_global_api(), self.base_filter)
            all_analyses = list(results)
            # Assert
            self.assert_deep_lists_equal(self.expected_result, all_analyses)

    def test_all_with_no_analyses_before(self):
        """Test no analyses exists, need to try fetch new analyses."""
        # Arrange
        with self.add_mock_response(self.normal_result):
            self.base_filter['limit'] = 2
            # Act
            results = AnalysesHistoryResult(FILE_ANALYSES_REQUEST, get_global_api(), self.base_filter)
            all_analyses = results.all()
            # Assert
            self.assert_deep_lists_equal(self.expected_result, all_analyses)

    def test_all_when_fetched_analyses_fetches_new_analyses(self):
        """
        Test all there are analyses exists, need to try fetch new analyses.
        """
        # Arrange
        self.normal_result['total_count'] = 4
        with self.add_mock_response(self.normal_result) as mock:
            self.normal_result['analyses'][0]['account_id'] = str(uuid.uuid4())
            self.expected_result.extend(copy.deepcopy(self.normal_result['analyses']))
            mock.add('POST',
                     url=self.full_url + FILE_ANALYSES_REQUEST,
                     status=HTTPStatus.OK,
                     json=self.normal_result)

            self.base_filter['limit'] = 2
            results = AnalysesHistoryResult(
                FILE_ANALYSES_REQUEST,
                get_global_api(),
                self.base_filter
            )
            result_iter = iter(results)
            next(result_iter)
            next(result_iter)

            # Act
            all_analyses = results.all()
            # Assert
            self.assert_deep_lists_equal(self.expected_result, all_analyses)

    def test_file_analyses_history_happy_flow(self):
        """Simple usage of file analyses history request using the SDK."""
        with self.add_mock_response(self.normal_result):
            results = query_file_analyses_history(
                start_date=self.start_date,
                end_date=self.end_date,
                aggregated_view=False,
                sources=["xsoar"],
                verdicts=['malicious'],
                file_hash='8d1131e418bdca5fb1abbb270c7cab46f169babcf7417cbf8557d2f3fe8e6b86',
                family_names=['bla'],
                file_name='hotmet.arm7',
            )
            for result in results:
                assert result

    def test_endpoint_analyses_history_happy_flow(self):
        """Simple usage of endpoint analyses history request using the SDK."""
        with self.add_mock_response(self.normal_result, request_url_path=ENDPOINT_ANALYSES_REQUEST):
            results = query_endpoint_analyses_history(
                start_date=self.start_date,
                end_date=self.end_date,
                aggregated_view=False,
                sources=["xsoar"],
                verdicts=['malicious'],
            )
            for result in results:
                assert result

    def test_url_analyses_history_happy_flow(self):
        """Simple usage of url analyses history request using the SDK."""
        with self.add_mock_response(self.normal_result, request_url_path=URL_ANALYSES_REQUEST):
            results = query_url_analyses_history(
                start_date=self.start_date,
                end_date=self.end_date,
                aggregated_view=False,
                sources=["xsoar"],
                verdicts=['malicious'],
                sub_verdicts=['phishing'],
                did_download_file=True,
                submitted_url='https://example_trusted.com'
            )
            for result in results:
                assert result
