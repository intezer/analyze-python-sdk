import sys
import unittest

from intezer_sdk import consts
from intezer_sdk.api import set_global_api


class BaseTest(unittest.TestCase):
    def setUp(self):
        self.full_url = consts.BASE_URL + consts.API_VERSION
        consts.CHECK_STATUS_INTERVAL = 0

        # Python 2 support
        if sys.version_info[0] < 3:
            self.patch_prop = '__builtin__.open'
        else:
            self.patch_prop = 'builtins.open'

        set_global_api()
