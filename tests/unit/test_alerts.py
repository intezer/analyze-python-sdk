import datetime
import hashlib
import uuid
from http import HTTPStatus

import responses

from intezer_sdk import errors
from intezer_sdk.alerts import Alert
from intezer_sdk.alerts import get_alerts_by_alert_ids
from intezer_sdk.consts import AlertStatusCode
from tests.unit.base_test import BaseTest
from tests.utils import load_binary_file_from_resources


class AlertsSpec(BaseTest):
    def _mock_alert_search(self, mock):
        mock.add('GET',
                 url=f'{self.full_url}/alerts/search',
                 status=HTTPStatus.OK,
                 json={'result': {
                     'alerts_count': 1,
                     'alerts': [{
                         'alert_id': 'alert_id',
                         'alert_verdict': 'alert_verdict',
                         'alert_source': 'alert_source',
                         'risk_level': 'risk_level',
                         'risk_category': 'risk_category',
                         'family_id': 'family_id',
                         'threat_name': 'threat_name',
                         'family_name': 'family_name',
                         'triage_result': {
                             'alert_verdict': 'alert_verdict',
                             'alert_verdict_display': 'Alert Verdict Display',
                             'families': [],
                             'family_id': 'family_id',
                             'family_name': 'family_name',
                             'risk_category': 'risk_category',
                             'risk_category_display': 'Risk Category Display',
                             'risk_level': 'risk_level',
                             'threat_name': 'threat_name',
                         }
                     }]}})

    def test_get_alerts_by_alert_ids(self):
        # Arrange
        with responses.RequestsMock() as mock:
            self._mock_alert_search(mock)
            # Act
            alerts_amount, alerts_details = get_alerts_by_alert_ids(['alert_id'])

            # Assert
            self.assertEqual(alerts_amount, 1)
            self.assertEqual(alerts_details[0]['alert_id'], 'alert_id')

    def test_get_alerts_by_alerts_ids(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/alerts/search',
                     status=HTTPStatus.OK,
                     json={'result': {
                         'alerts_count': 0,
                         'alerts': []
                     }})
            # Act
            alerts_amount, alerts_details = get_alerts_by_alert_ids(['alert_id_2'])

            # Assert
            self.assertEqual(alerts_amount, 0)
            self.assertEqual(alerts_details, [])

    def test_alert_from_id(self):
        # Arrange
        case_association_time_str = '2026-04-29T12:34:56+00:00'
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/alerts/get-by-id',
                     status=HTTPStatus.OK,
                     json={'result': {'case_association_time': case_association_time_str},
                           'status': 'success'})
            # Act
            alert = Alert.from_id('alert_id', environment='environment')

            # Assert
            self.assertEqual(alert.alert_id, 'alert_id')
            self.assertEqual(alert.case_association_time,
                             datetime.datetime.fromisoformat(case_association_time_str))


    def test_alert_from_id_raises_conflict_when_environment_is_ambiguous(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/alerts/get-by-id',
                     status=HTTPStatus.CONFLICT,
                     json={'error': 'Alert exists in multiple environments'})
            # Act & Assert
            with self.assertRaises(errors.AlertConflictError):
                Alert.from_id('alert_id')

    def test_alert_from_id_waits_from_completion(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.get(url=f'{self.full_url}/alerts/get-by-id',
                     status=HTTPStatus.OK,
                     json={'result': {}, 'status': 'in_progress'})
            mock.get(url=f'{self.full_url}/alerts/get-by-id',
                     status=HTTPStatus.OK,
                     json={'result': {}, 'status': 'success'})
            # Act
            alert = Alert.from_id('alert_id', environment='environment', wait=True)

            # Assert
            self.assertEqual(alert.alert_id, 'alert_id')

    def test_ingest_binary_alert_success(self):
        # Arrange
        raw_alert = load_binary_file_from_resources('binary_alerts/test.eml')
        alert_id = hashlib.sha256(raw_alert.read()).hexdigest()

        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/alerts/ingest/binary',
                     status=HTTPStatus.OK,
                     json={'result': True, 'alert_id': alert_id})
            # Act
            alert = Alert.send_phishing_email(raw_email=raw_alert,
                                              alert_sender='alert_sender')

            # Assert
            self.assertEqual(alert.alert_id, alert_id)

    def test_get_raw_alert_data(self):
        # Arrange
        alert_id = 'test-alert-id'
        environment = 'test-env'
        expected_raw_data = {
            'result_url': 'https://example.com/download/alert-data',
            'metadata': {'environment': environment, 'raw_data_type': 'raw_alert'}
        }

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/alerts/{alert_id}/raw-data',
                     json=expected_raw_data,
                     status=HTTPStatus.OK)

            alert = Alert(alert_id=alert_id)

            # Act
            result_data = alert.get_raw_data(environment=environment)

            # Assert
            self.assertEqual(result_data, expected_raw_data)

    def test_alert_notify_success(self):
        # Arrange
        alert_id = 'test_alert_id'
        expected_channels = ['channel-123-456', 'channel-789-012']
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/alerts/get-by-id',
                     status=HTTPStatus.OK,
                     json={'result': {'environment': 'environment'}, 'status': 'success'})
            mock.add('POST',
                     url=f'{self.full_url}/alerts/{alert_id}/notify',
                     status=HTTPStatus.OK,
                     json={'notified_channels': expected_channels})

            # Act
            alert = Alert.from_id(alert_id)
            notified_channels = alert.notify()

            # Assert
            self.assertEqual(notified_channels, expected_channels)

    def test_alert_notify_returns_empty_list_when_no_channels_in_response(self):
        # Arrange
        alert_id = 'test_alert_id'
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/alerts/get-by-id',
                     status=HTTPStatus.OK,
                     json={'result': {'environment': 'environment'}, 'status': 'success'})
            mock.add('POST',
                     url=f'{self.full_url}/alerts/{alert_id}/notify',
                     status=HTTPStatus.OK,
                     json={'result': True})

            # Act
            alert = Alert.from_id(alert_id)
            notified_channels = alert.notify()

            # Assert
            self.assertEqual(notified_channels, [])

    def test_alert_notify_raises_alert_not_found_error_when_alert_not_found(self):
        # Arrange
        alert = Alert(alert_id='test_alert_id')
        alert.status = AlertStatusCode.NOT_FOUND

        # Act & Assert
        with self.assertRaises(errors.AlertNotFoundError):
            alert.notify()

    def test_alert_notify_raises_alert_in_progress_error_when_alert_in_progress(self):
        # Arrange
        alert = Alert(alert_id='test_alert_id')
        alert.status = AlertStatusCode.IN_PROGRESS

        # Act & Assert
        with self.assertRaises(errors.AlertInProgressError):
            alert.notify()


    def test_alert_from_id_with_allow_partial_true_extracts_available_fields(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/alerts/get-by-id',
                     status=HTTPStatus.OK,
                     json={'result': {
                         'environment': 'environment',
                         'source': 'source',
                         'sender': 'sender',
                         'intezer_alert_url': 'alert_url'
                     }, 'status': 'in_progress'})
            # Act
            alert = Alert.from_id('alert_id', environment='environment', allow_partial=True)

            # Assert
            self.assertEqual(alert.status, AlertStatusCode.IN_PROGRESS)
            self.assertEqual(alert.source, 'source')
            self.assertEqual(alert.sender, 'sender')
            self.assertEqual(alert.intezer_alert_url, 'alert_url')
            self.assertIsNone(alert.verdict)
            self.assertIsNone(alert.family_name)

    def test_alert_from_id_with_allow_partial_false_raises_error_on_in_progress(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/alerts/get-by-id',
                     status=HTTPStatus.OK,
                     json={'result': {'environment': 'environment'}, 'status': 'in_progress'})
            # Act & Assert
            with self.assertRaises(errors.AlertInProgressError):
                Alert.from_id('alert_id', environment='environment', allow_partial=False)

    def test_alert_from_id_with_allow_partial_default_raises_error_on_in_progress(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/alerts/get-by-id',
                     status=HTTPStatus.OK,
                     json={'result': {'environment': 'environment'}, 'status': 'in_progress'})
            # Act & Assert
            with self.assertRaises(errors.AlertInProgressError):
                Alert.from_id('alert_id', environment='environment')

    def test_alert_from_id_with_wait_true_ignores_allow_partial(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/alerts/get-by-id',
                     status=HTTPStatus.OK,
                     json={'result': {'environment': 'environment'}, 'status': 'in_progress'})
            mock.add('GET',
                     url=f'{self.full_url}/alerts/get-by-id',
                     status=HTTPStatus.OK,
                     json={'result': {
                         'environment': 'environment',
                         'triage_result': {
                             'alert_verdict': 'alert_verdict',
                             'family_name': 'family_name'
                         }
                     }, 'status': 'success'})
            # Act
            alert = Alert.from_id('alert_id', environment='environment', wait=True, allow_partial=True)

            # Assert
            self.assertEqual(alert.status, AlertStatusCode.FINISHED)
            self.assertEqual(alert.verdict, 'alert_verdict')
            self.assertEqual(alert.family_name, 'family_name')

    def test_partial_alert_result_method_returns_partial_data(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/alerts/get-by-id',
                     status=HTTPStatus.OK,
                     json={'result': {'environment': 'environment', 'source': 'source'}, 'status': 'in_progress'})
            alert = Alert.from_id('alert_id', environment='environment', allow_partial=True)

            # Act
            result = alert.result()

            # Assert
            self.assertIsNotNone(result)
            self.assertEqual(result['environment'], 'environment')
            self.assertEqual(result['source'], 'source')

    def test_partial_alert_result_method_raises_error_when_allow_partial_false(self):
        # Arrange
        alert = Alert(alert_id='alert_id', environment='environment')
        alert.status = AlertStatusCode.IN_PROGRESS

        # Act & Assert
        with self.assertRaises(errors.AlertInProgressError):
            alert.result()

    def test_partial_alert_fetch_scans_raises_error(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/alerts/get-by-id',
                     status=HTTPStatus.OK,
                     json={'result': {'environment': 'environment'}, 'status': 'in_progress'})
            alert = Alert.from_id('alert_id', environment='environment', allow_partial=True)

            # Act & Assert
            with self.assertRaises(errors.AlertInProgressError):
                alert.fetch_scans()

    def test_partial_alert_notify_raises_error(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/alerts/get-by-id',
                     status=HTTPStatus.OK,
                     json={'result': {'environment': 'environment'}, 'status': 'in_progress'})
            alert = Alert.from_id('alert_id', environment='environment', allow_partial=True)

            # Act & Assert
            with self.assertRaises(errors.AlertInProgressError):
                alert.notify()
