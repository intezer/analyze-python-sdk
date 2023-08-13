import datetime
import time
import unittest
from http import HTTPStatus

import responses

from intezer_sdk import consts
from intezer_sdk import errors
from intezer_sdk.api import IntezerApiClient
from intezer_sdk.api import raise_for_status
from intezer_sdk.api import set_global_api


class BaseTest(unittest.TestCase):
    def setUp(self):
        self.full_url = consts.BASE_URL + consts.API_VERSION
        consts.CHECK_STATUS_INTERVAL = 0
        self.patch_prop = 'builtins.open'

        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/get-access-token',
                     status=HTTPStatus.OK,
                     json={'result': 'access-token'})
            set_global_api().authenticate()


class ApiSpec(unittest.TestCase):
    def setUp(self) -> None:
        self.full_url = consts.BASE_URL + consts.API_VERSION

    def test_renew_token(self):
        with responses.RequestsMock(assert_all_requests_are_fired=True) as mock:
            token_expiration = datetime.datetime.now() + datetime.timedelta(seconds=20.2)
            mock.add('POST',
                     url=f'{self.full_url}/get-access-token',
                     status=HTTPStatus.OK,
                     json={'result': 'access-token', 'expire_at': token_expiration.timestamp()})
            api = set_global_api()
            api.authenticate()
            mock.reset()
            mock.add('POST',
                     url=f'{self.full_url}/some-route',
                     status=HTTPStatus.OK)
            response = api.request_with_refresh_expired_access_token('POST', '/some-route')
            response.raise_for_status()
            time.sleep(0.2)
            mock.reset()
            mock.add('POST',
                     url=f'{self.full_url}/some-route',
                     status=HTTPStatus.OK)
            mock.add('POST',
                     url=f'{self.full_url}/get-access-token',
                     status=HTTPStatus.OK,
                     json={'result': 'access-token', 'expire_at': time.time()})

            response = api.request_with_refresh_expired_access_token('POST', '/some-route')
            response.raise_for_status()

    def test_api_raise_insufficient_permissions_error_when_insufficient_permissions_received(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/get-access-token',
                     status=HTTPStatus.OK,
                     json={'result': 'access-token', 'expire_at': 2166920067})
            api = set_global_api()
            api.authenticate()

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     f'{self.full_url}/some-route',
                     status=HTTPStatus.FORBIDDEN,
                     json={'error': 'Insufficient Permissions'})
            response = api.request_with_refresh_expired_access_token('GET', '/some-route')

            with self.assertRaises(errors.InsufficientPermissionsError):
                raise_for_status(response)

    def test_api_raise_invalid_api_key_error_when_unauthorized_received(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/get-access-token',
                     status=HTTPStatus.OK,
                     json={'result': 'access-token', 'expire_at': 2166920067})
            api = set_global_api()
            api.authenticate()

        with responses.RequestsMock() as mock:
            mock.add('GET', f'{self.full_url}/some-route', status=HTTPStatus.UNAUTHORIZED)
            response = api.request_with_refresh_expired_access_token('GET', '/some-route')

            with self.assertRaises(errors.InvalidApiKeyError):
                raise_for_status(response)

    def test_is_intezer_site_available(self):
        # Arrange
        api = IntezerApiClient(base_url='', api_version='')
        api.full_url = self.full_url
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/is-available',
                     status=HTTPStatus.OK,
                     json={'is_available': True})
            # Act & Assert
            self.assertTrue(api.is_available())

    def test_is_intezer_site_available_website_not_available(self):
        # Arrange
        api = IntezerApiClient(base_url='', api_version='')
        api.full_url = self.full_url
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/is-available',
                     status=HTTPStatus.OK,
                     json={'is_available': False})
            # Act & Assert
            self.assertFalse(api.is_available())

    def test_is_intezer_site_available_server_no_response(self):
        # Arrange
        api = IntezerApiClient(base_url='', api_version='')
        api.full_url = self.full_url
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/is-available',
                     status=HTTPStatus.GATEWAY_TIMEOUT,
                     json={})
            # Act & Assert
            self.assertFalse(api.is_available())
