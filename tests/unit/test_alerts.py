from http import HTTPStatus

import responses

from intezer_sdk.alerts import Alerts
from tests.unit.base_test import BaseTest


class AlertsSpec(BaseTest):
    def test_get_alerts_by_alert_ids(self):
        # Arrange
        with responses.RequestsMock() as mock:
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
                         }]}})
            alerts_api = Alerts()

            # Act
            alerts_amount, alerts_details = alerts_api.get_alerts_by_alert_ids(['alert_id'])

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
            alerts_api = Alerts()

            # Act
            alerts_amount, alerts_details = alerts_api.get_alerts_by_alert_ids(['alert_id_2'])

            # Assert
            self.assertEqual(alerts_amount, 0)
            self.assertEqual(alerts_details, [])
