import hashlib
from http import HTTPStatus
import uuid

import responses

from intezer_sdk.alerts import get_alerts_by_alert_ids
from intezer_sdk.alerts import Alert
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

    def test_ingest_alert_success(self):
        # Arrange
        alert_id = str(uuid.uuid4())
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/alerts/ingest',
                     status=HTTPStatus.OK,
                     json={'result': True, 'alert_id': alert_id})
            # Act
            alert = Alert.send(raw_alert={'alert_id': 'alert_id'},
                               alert_mapping={'some': 'mapping'},
                               source='source',
                               environment='environment',
                               display_fields=['display_fields'],
                               alert_sender='alert_sender',
                               )

            # Assert
            self.assertEqual(alert.alert_id, alert_id)

    def test_alert_from_id(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/alerts/get-by-id',
                     status=HTTPStatus.OK,
                     json={'result': {}, 'status': 'success'})
            # Act
            alert = Alert.from_id('alert_id')

            # Assert
            self.assertEqual(alert.alert_id, 'alert_id')


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
            alert = Alert.from_id('alert_id', wait=True)

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
