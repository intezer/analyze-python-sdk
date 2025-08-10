import datetime
from http import HTTPStatus

import responses

from intezer_sdk import errors
from intezer_sdk.api import get_global_api
from intezer_sdk.incidents import Incident
from intezer_sdk.incidents import generate_incidents_history_search_filters
from intezer_sdk.incidents import query_incidents_history
from intezer_sdk.incidents_results import IncidentsHistoryResult
from tests.unit.base_test import BaseTest


class IncidentsSpec(BaseTest):
    def test_generate_incidents_history_search_filters_with_all_parameters(self):
        # Arrange
        incident_ids = ['incident1', 'incident2']
        environments = ['env1', 'env2']
        offset = 10
        limit = 50
        time_filter_type = ['creation_time']
        start_time = datetime.datetime(2023, 1, 1, 12, 0, 0)
        end_time = datetime.datetime(2023, 1, 2, 12, 0, 0)
        sources = ['source1', 'source2']
        senders = ['sender1', 'sender2']
        severities = ['high', 'medium']
        statuses = ['open', 'closed']
        names = ['incident_name1', 'incident_name2']
        related_alert_ids = ['alert1', 'alert2']
        risk_categories = ['malware', 'phishing']
        response_statuses = ['responded', 'pending']
        free_text = 'test search'
        sort_by = ['creation_time']
        sort_order = 'desc'
        include_raw_incident = True

        # Act
        result = generate_incidents_history_search_filters(
            incident_ids=incident_ids,
            environments=environments,
            offset=offset,
            limit=limit,
            time_filter_type=time_filter_type,
            start_time=start_time,
            end_time=end_time,
            sources=sources,
            senders=senders,
            severities=severities,
            statuses=statuses,
            names=names,
            related_alert_ids=related_alert_ids,
            risk_categories=risk_categories,
            response_statuses=response_statuses,
            free_text=free_text,
            sort_by=sort_by,
            sort_order=sort_order,
            include_raw_incident=include_raw_incident
        )

        # Assert
        self.assertEqual(result['incident_ids'], incident_ids)
        self.assertEqual(result['environments'], environments)
        self.assertEqual(result['offset'], offset)
        self.assertEqual(result['limit'], limit)
        self.assertEqual(result['time_filter_type'], time_filter_type)
        self.assertEqual(result['start_time'], start_time.timestamp())
        self.assertEqual(result['end_time'], end_time.timestamp())
        self.assertEqual(result['sources'], sources)
        self.assertEqual(result['senders'], senders)
        self.assertEqual(result['severities'], severities)
        self.assertEqual(result['statuses'], statuses)
        self.assertEqual(result['names'], names)
        self.assertEqual(result['related_alert_ids'], related_alert_ids)
        self.assertEqual(result['risk_categories'], risk_categories)
        self.assertEqual(result['response_statuses'], response_statuses)
        self.assertEqual(result['free_text'], free_text)
        self.assertEqual(result['sort_by'], sort_by)
        self.assertEqual(result['sort_order'], sort_order)
        self.assertEqual(result['include_raw_incident'], include_raw_incident)

    def test_generate_incidents_history_search_filters_with_none_parameters(self):
        # Arrange & Act
        result = generate_incidents_history_search_filters()

        # Assert
        self.assertEqual(result, {})

    def test_generate_incidents_history_search_filters_with_datetime_none(self):
        # Arrange & Act
        result = generate_incidents_history_search_filters(
            start_time=None,
            end_time=None
        )

        # Assert
        self.assertEqual(result, {})

    def test_query_incidents_history_returns_incidents_incidents_result(self):
        # Arrange
        incident_ids = ['incident1']

        # Act
        result = query_incidents_history(incident_ids=incident_ids)

        # Assert
        self.assertIsInstance(result, IncidentsHistoryResult)

    def test_incident_init(self):
        # Arrange
        incident_id = 'test_incident_id'

        # Act
        incident = Incident(incident_id)

        # Assert
        self.assertEqual(incident.incident_id, incident_id)
        self.assertIsNone(incident.name)
        self.assertIsNone(incident.source)
        self.assertIsNone(incident.sender)
        self.assertIsNone(incident.risk_category)
        self.assertIsNone(incident.risk_level)
        self.assertIsNone(incident.intezer_incident_url)

    def test_incident_fetch_info_success(self):
        # Arrange
        incident_id = 'test_incident_id'
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/incidents/get-by-id',
                     status=HTTPStatus.OK,
                     json={
                         'result': {
                             'source': 'test_source',
                             'sender': 'test_sender',
                             'incident': {'name': 'test_incident_name'},
                             'triage_summary': {
                                 'risk_category': 'malware',
                                 'risk_level': 'high'
                             },
                             'intezer_incident_url': 'https://analyze.intezer.com/incidents/test_incident_id'
                         }
                     })

            incident = Incident(incident_id)

            # Act
            incident.fetch_info()

            # Assert
            self.assertEqual(incident.source, 'test_source')
            self.assertEqual(incident.sender, 'test_sender')
            self.assertEqual(incident.name, 'test_incident_name')
            self.assertEqual(incident.risk_category, 'malware')
            self.assertEqual(incident.risk_level, 'high')
            self.assertEqual(incident.intezer_incident_url, 'https://analyze.intezer.com/incidents/test_incident_id')

    def test_incident_fetch_info_without_incident_id_raises_error(self):
        # Arrange
        incident = Incident()

        # Act & Assert
        with self.assertRaises(ValueError) as context:
            incident.fetch_info()

        self.assertEqual(str(context.exception), "Incident ID is required to fetch incident info.")

    def test_incident_fetch_info_not_found_raises_error(self):
        # Arrange
        incident_id = 'test_incident_id'
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/incidents/get-by-id',
                     status=HTTPStatus.NOT_FOUND,
                     json={'error': 'Incident not found'})

            incident = Incident(incident_id)

            # Act & Assert
            with self.assertRaises(errors.IncidentNotFoundError):
                incident.fetch_info()

    def test_incident_result_returns_raw_data(self):
        # Arrange
        incident_id = 'test_incident_id'
        expected_result = {
            'source': 'test_source',
            'sender': 'test_sender',
            'incident': {'name': 'test_incident_name'}
        }

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/incidents/get-by-id',
                     status=HTTPStatus.OK,
                     json={'result': expected_result})

            incident = Incident(incident_id)
            incident.fetch_info()

            # Act
            result = incident.result()

            # Assert
            self.assertEqual(result, expected_result)

    def test_incident_result_returns_none_when_no_data_fetched(self):
        # Arrange
        incident = Incident('test_incident_id')

        # Act
        result = incident.result()

        # Assert
        self.assertIsNone(result)

    def test_incident_from_id_success(self):
        # Arrange
        incident_id = 'test_incident_id'
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/incidents/get-by-id',
                     status=HTTPStatus.OK,
                     json={
                         'result': {
                             'source': 'test_source',
                             'sender': 'test_sender',
                             'incident': {'name': 'test_incident_name'},
                             'triage_summary': {
                                 'risk_category': 'malware',
                                 'risk_level': 'high'
                             },
                             'intezer_incident_url': 'https://analyze.intezer.com/incidents/test_incident_id'
                         }
                     })

            # Act
            incident = Incident.from_id(incident_id)

            # Assert
            self.assertEqual(incident.incident_id, incident_id)
            self.assertEqual(incident.source, 'test_source')
            self.assertEqual(incident.sender, 'test_sender')
            self.assertEqual(incident.name, 'test_incident_name')
            self.assertEqual(incident.risk_category, 'malware')
            self.assertEqual(incident.risk_level, 'high')

    def test_get_raw_incident_data(self):
        # Arrange
        incident_id = "test-incident-id"
        environment = "test-env"
        expected_raw_data = {
            "result_url": "https://example.com/download/incident-data",
            "metadata": {"environment": environment, "raw_data_type": "raw_incident"}
        }
        
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/incidents/{incident_id}/raw-data',
                     json=expected_raw_data,
                     status=HTTPStatus.OK)
            
            incident = Incident(incident_id=incident_id)
            
            # Act
            result_data = incident.get_raw_data(environment=environment)
            
            # Assert
            self.assertEqual(result_data, expected_raw_data)


class IncidentsHistoryResultSpec(BaseTest):
    def test_incidents_history_result_init(self):
        # Arrange
        request_url_path = '/incidents/search'
        filters = {'incident_ids': ['incident1']}
        api = get_global_api()

        # Act
        result = IncidentsHistoryResult(request_url_path, api, filters)

        # Assert
        self.assertEqual(result._request_url_path, request_url_path)
        self.assertEqual(result._api, api)
        self.assertEqual(result.filters, filters)

    def test_incidents_history_result_fetch_history_success(self):
        # Arrange
        request_url_path = '/incidents/search'
        filters = {'incident_ids': ['incident1']}
        incidents_data = [
            {
                'incident_id': 'incident1',
                'name': 'Test Incident',
                'source': 'test_source',
                'risk_level': 'high'
            }
        ]

        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/incidents/search',
                     status=HTTPStatus.OK,
                     json={
                         'result': {
                             'incidents_count': 1,
                             'incidents': incidents_data
                         }
                     })

            result = IncidentsHistoryResult(request_url_path, get_global_api(), filters)

            # Act
            count, incidents = result._fetch_history(request_url_path, filters)

            # Assert
            self.assertEqual(count, 1)
            self.assertEqual(incidents, incidents_data)

    def test_incidents_history_result_fetch_history_empty_result(self):
        # Arrange
        request_url_path = '/incidents/search'
        filters = {'incident_ids': ['nonexistent_incident']}

        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/incidents/search',
                     status=HTTPStatus.OK,
                     json={
                         'result': {
                             'incidents_count': 0,
                             'incidents': []
                         }
                     })

            result = IncidentsHistoryResult(request_url_path, get_global_api(), filters)

            # Act
            count, incidents = result._fetch_history(request_url_path, filters)

            # Assert
            self.assertEqual(count, 0)
            self.assertEqual(incidents, [])
