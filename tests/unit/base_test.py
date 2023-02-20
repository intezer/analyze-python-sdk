import datetime
import time
import unittest
from http import HTTPStatus

import responses

from intezer_sdk import consts
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


class TokenRefreshSpec(unittest.TestCase):
    def setUp(self) -> None:
        self.full_url = consts.BASE_URL + consts.API_VERSION

    def test_renew_token(self):
        with responses.RequestsMock(assert_all_requests_are_fired=True) as mock:
            mock.add('POST',
                     url=f'{self.full_url}/get-access-token',
                     status=HTTPStatus.OK,
                     json={'result': 'access-token','expire_at': (datetime.datetime.utcnow() + datetime.timedelta(seconds=20.2)).timestamp()})
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





