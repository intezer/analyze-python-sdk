from http import HTTPStatus

import responses

from intezer_sdk import errors
from intezer_sdk.api import get_global_api
from intezer_sdk.cases import Case
from intezer_sdk.cases import generate_cases_search_filters
from intezer_sdk.cases import query_cases_history
from intezer_sdk.cases_results import CasesHistoryResult
from tests.unit.base_test import BaseTest


class CasesSpec(BaseTest):
    def test_generate_cases_search_filters_with_all_parameters(self):
        # Arrange
        case_ids = ['case1', 'case2']
        exclude_case_ids = ['case3']
        time_range_start = 1700000000
        time_range_end = 1700100000
        time_range_field = 'creation_time'
        sources = ['source1']
        free_text = 'search me'
        sub_tenant_names = ['tenant1']
        devices = {'hostnames': ['host1']}
        users = {'user_emails': ['a@b.com']}
        alert_identifiers = [{'alert_id': 'alert1', 'environment': 'env1'}]
        risk_categories = ['malware']
        case_verdicts = ['malicious']
        response_statuses = ['responded']
        case_statuses = ['new']
        assigned_account_ids = ['account1']
        priorities = ['high']
        external_ticket_vendors = ['jira']
        analyst_verdicts = ['true_positive']
        offset = 10
        limit = 50
        search_mode = 'and'
        sort_by = 'creation_time'

        # Act
        result = generate_cases_search_filters(
            case_ids=case_ids,
            exclude_case_ids=exclude_case_ids,
            time_range_start=time_range_start,
            time_range_end=time_range_end,
            time_range_field=time_range_field,
            sources=sources,
            free_text=free_text,
            sub_tenant_names=sub_tenant_names,
            devices=devices,
            users=users,
            alert_identifiers=alert_identifiers,
            risk_categories=risk_categories,
            case_verdicts=case_verdicts,
            response_statuses=response_statuses,
            case_statuses=case_statuses,
            assigned_account_ids=assigned_account_ids,
            priorities=priorities,
            external_ticket_vendors=external_ticket_vendors,
            analyst_verdicts=analyst_verdicts,
            offset=offset,
            limit=limit,
            search_mode=search_mode,
            sort_by=sort_by,
        )

        # Assert
        payload = result['payload']
        self.assertEqual(payload['case_ids'], case_ids)
        self.assertEqual(payload['exclude_case_ids'], exclude_case_ids)
        self.assertEqual(payload['time_range_start'], time_range_start)
        self.assertEqual(payload['time_range_end'], time_range_end)
        self.assertEqual(payload['time_range_field'], time_range_field)
        self.assertEqual(payload['sources'], sources)
        self.assertEqual(payload['free_text'], free_text)
        self.assertEqual(payload['sub_tenant_names'], sub_tenant_names)
        self.assertEqual(payload['devices'], devices)
        self.assertEqual(payload['users'], users)
        self.assertEqual(payload['alert_identifiers'], alert_identifiers)
        self.assertEqual(payload['risk_categories'], risk_categories)
        self.assertEqual(payload['case_verdicts'], case_verdicts)
        self.assertEqual(payload['response_statuses'], response_statuses)
        self.assertEqual(payload['case_statuses'], case_statuses)
        self.assertEqual(payload['assigned_account_ids'], assigned_account_ids)
        self.assertEqual(payload['priorities'], priorities)
        self.assertEqual(payload['external_ticket_vendors'], external_ticket_vendors)
        self.assertEqual(payload['analyst_verdicts'], analyst_verdicts)
        self.assertEqual(result['offset'], offset)
        self.assertEqual(result['limit'], limit)
        self.assertEqual(result['search_mode'], search_mode)
        self.assertEqual(result['sort_by'], sort_by)

    def test_generate_cases_search_filters_with_none_parameters(self):
        # Arrange & Act
        result = generate_cases_search_filters()

        # Assert
        self.assertEqual(result, {'payload': {}})

    def test_query_cases_history_returns_cases_history_result(self):
        # Arrange
        case_ids = ['case1']

        # Act
        result = query_cases_history(case_ids=case_ids)

        # Assert
        self.assertIsInstance(result, CasesHistoryResult)
        self.assertEqual(result.filters['payload']['case_ids'], case_ids)
        self.assertEqual(result.filters['offset'], 0)
        self.assertEqual(result.filters['limit'], 100)

    def test_case_init(self):
        # Arrange
        case_id = 'test_case_id'

        # Act
        case = Case(case_id)

        # Assert
        self.assertEqual(case.case_id, case_id)
        self.assertIsNone(case.case_title)
        self.assertIsNone(case.case_status)
        self.assertIsNone(case.case_priority)
        self.assertIsNone(case.alerts_count)
        self.assertIsNone(case.risk_category)
        self.assertIsNone(case.case_verdict)
        self.assertIsNone(case.response_status)
        self.assertIsNone(case.analyst_verdict)
        self.assertIsNone(case.intezer_case_url)

    def test_case_fetch_info_success(self):
        # Arrange
        case_id = 'test_case_id'
        case_payload = {
            'case_title': 'Test Case',
            'case_status': 'new',
            'case_priority': 'high',
            'alerts_count': 3,
            'case_sources': ['source1'],
            'case_tags': ['tag1'],
            'analyst_verdict': 'true_positive',
            'intezer_case_url': 'https://analyze.intezer.com/cases/test_case_id',
            'case_triage': {
                'risk_category': 'malware',
                'case_verdict': 'malicious',
                'response_status': 'responded',
            },
        }
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/cases/{case_id}',
                     status=HTTPStatus.OK,
                     json={'result': case_payload})

            case = Case(case_id)

            # Act
            case.fetch_info()

            # Assert
            self.assertEqual(case.case_title, 'Test Case')
            self.assertEqual(case.case_status, 'new')
            self.assertEqual(case.case_priority, 'high')
            self.assertEqual(case.alerts_count, 3)
            self.assertEqual(case.case_sources, ['source1'])
            self.assertEqual(case.case_tags, ['tag1'])
            self.assertEqual(case.analyst_verdict, 'true_positive')
            self.assertEqual(case.intezer_case_url,
                             'https://analyze.intezer.com/cases/test_case_id')
            self.assertEqual(case.risk_category, 'malware')
            self.assertEqual(case.case_verdict, 'malicious')
            self.assertEqual(case.response_status, 'responded')

    def test_case_fetch_info_not_found_raises_error(self):
        # Arrange
        case_id = 'missing_case_id'
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/cases/{case_id}',
                     status=HTTPStatus.NOT_FOUND,
                     json={'error': 'Case not found'})

            case = Case(case_id)

            # Act & Assert
            with self.assertRaises(errors.CaseNotFoundError):
                case.fetch_info()

    def test_case_fetch_info_missing_triage_does_not_fail(self):
        # Arrange
        case_id = 'test_case_id'
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/cases/{case_id}',
                     status=HTTPStatus.OK,
                     json={'result': {'case_title': 'Test Case'}})

            case = Case(case_id)

            # Act
            case.fetch_info()

            # Assert
            self.assertEqual(case.case_title, 'Test Case')
            self.assertIsNone(case.risk_category)
            self.assertIsNone(case.case_verdict)
            self.assertIsNone(case.response_status)

    def test_case_result_returns_raw_data(self):
        # Arrange
        case_id = 'test_case_id'
        expected_result = {'case_title': 'Test Case', 'case_status': 'new'}

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/cases/{case_id}',
                     status=HTTPStatus.OK,
                     json={'result': expected_result})

            case = Case(case_id)
            case.fetch_info()

            # Act
            result = case.result()

            # Assert
            self.assertEqual(result, expected_result)

    def test_case_result_returns_none_when_no_data_fetched(self):
        # Arrange
        case = Case('test_case_id')

        # Act
        result = case.result()

        # Assert
        self.assertIsNone(result)

    def test_case_from_id_success(self):
        # Arrange
        case_id = 'test_case_id'
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/cases/{case_id}',
                     status=HTTPStatus.OK,
                     json={
                         'result': {
                             'case_title': 'Test Case',
                             'case_status': 'new',
                             'case_priority': 'high',
                             'case_triage': {
                                 'risk_category': 'malware',
                                 'case_verdict': 'malicious',
                                 'response_status': 'responded',
                             },
                         }
                     })

            # Act
            case = Case.from_id(case_id)

            # Assert
            self.assertEqual(case.case_id, case_id)
            self.assertEqual(case.case_title, 'Test Case')
            self.assertEqual(case.case_status, 'new')
            self.assertEqual(case.case_priority, 'high')
            self.assertEqual(case.risk_category, 'malware')
            self.assertEqual(case.case_verdict, 'malicious')
            self.assertEqual(case.response_status, 'responded')

    def test_case_get_devices(self):
        # Arrange
        case_id = 'test_case_id'
        devices = [{'hostname': 'host1'}, {'hostname': 'host2'}]
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/cases/{case_id}/devices',
                     status=HTTPStatus.OK,
                     json={'result': {'devices': devices}})

            case = Case(case_id)

            # Act
            result = case.get_devices()

            # Assert
            self.assertEqual(result, devices)

    def test_case_get_users(self):
        # Arrange
        case_id = 'test_case_id'
        users = [{'user_email': 'a@b.com'}]
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/cases/{case_id}/users',
                     status=HTTPStatus.OK,
                     json={'result': {'users': users}})

            case = Case(case_id)

            # Act
            result = case.get_users()

            # Assert
            self.assertEqual(result, users)

    def test_case_get_ttps(self):
        # Arrange
        case_id = 'test_case_id'
        ttps = [{'ttp_id': 'T1059'}]
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/cases/{case_id}/ttps',
                     status=HTTPStatus.OK,
                     json={'result': {'ttps': ttps}})

            case = Case(case_id)

            # Act
            result = case.get_ttps()

            # Assert
            self.assertEqual(result, ttps)


class CasesHistoryResultSpec(BaseTest):
    def test_cases_history_result_init(self):
        # Arrange
        request_url_path = '/cases/search'
        filters = {'payload': {'case_ids': ['case1']}, 'offset': 0, 'limit': 100}
        api = get_global_api()

        # Act
        result = CasesHistoryResult(request_url_path, api, filters)

        # Assert
        self.assertEqual(result._request_url_path, request_url_path)
        self.assertEqual(result._api, api)
        self.assertEqual(result.filters, filters)

    def test_cases_history_result_fetch_history_success(self):
        # Arrange
        request_url_path = '/cases/search'
        filters = {'payload': {'case_ids': ['case1']}, 'offset': 0, 'limit': 100}
        cases_data = [
            {
                'case_id': 'case1',
                'case_title': 'Test Case',
                'case_status': 'new',
                'case_priority': 'high',
            }
        ]

        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/cases/search',
                     status=HTTPStatus.OK,
                     json={
                         'result': {
                             'cases_count': 1,
                             'cases': cases_data,
                         }
                     })

            result = CasesHistoryResult(request_url_path, get_global_api(), filters)

            # Act
            count, cases = result._fetch_history(request_url_path, filters)

            # Assert
            self.assertEqual(count, 1)
            self.assertEqual(cases, cases_data)

    def test_cases_history_result_fetch_history_empty_result(self):
        # Arrange
        request_url_path = '/cases/search'
        filters = {'payload': {'case_ids': ['nonexistent']}, 'offset': 0, 'limit': 100}

        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/cases/search',
                     status=HTTPStatus.OK,
                     json={
                         'result': {
                             'cases_count': 0,
                             'cases': [],
                         }
                     })

            result = CasesHistoryResult(request_url_path, get_global_api(), filters)

            # Act
            count, cases = result._fetch_history(request_url_path, filters)

            # Assert
            self.assertEqual(count, 0)
            self.assertEqual(cases, [])
