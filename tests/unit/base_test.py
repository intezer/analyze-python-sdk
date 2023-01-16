import unittest

import responses

from intezer_sdk import consts
from intezer_sdk.api import get_global_api
from intezer_sdk.api import set_global_api


class BaseTest(unittest.TestCase):
    def setUp(self):
        self.full_url = consts.BASE_API_URL + consts.API_VERSION
        consts.CHECK_STATUS_INTERVAL = 0
        self.patch_prop = 'builtins.open'

        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=self.full_url + '/get-access-token',
                     status=200,
                     json={'result': 'access-token'})
            set_global_api()
            get_global_api().set_session()
