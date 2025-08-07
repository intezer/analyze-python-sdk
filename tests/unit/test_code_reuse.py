import json
import os
import unittest
from http import HTTPStatus
import responses

from intezer_sdk import consts
from intezer_sdk.api import set_global_api
from intezer_sdk.code_reuse import CodeReuse

TEST_HASH = "73c677dd3b264e7eb80e26e78ac9df1dba30915b5ce3b1bc1c83db52b9c6b30e"


def load_response_json(file_name: str) -> dict:
    path_to_file = os.path.join(os.path.dirname(
        __file__), "..", "resources", file_name)
    with open(path_to_file, 'rb') as file:
        return json.load(file)


class BaseTest(unittest.TestCase):
    def setUp(self):
        self.full_url = consts.BASE_URL + consts.API_VERSION
        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/get-access-token',
                     status=HTTPStatus.OK,
                     json={'result': 'access-token'})
            set_global_api().authenticate()


class CodeReuseSpec(BaseTest):

    def test_code_reuse_by_block(self):
        with responses.RequestsMock() as mock:
            mock.add("POST",
                     url=consts.ANALYZE_URL +
                     f'/api/v2-0/files/{TEST_HASH}/code-reuse-by-code-block',
                     status=HTTPStatus.OK,
                     json=load_response_json("code_reuse_block_response.json"))
            mock.add("GET",
                     url=consts.ANALYZE_URL +
                     "/api/v2-0/analyses/51ea282b-0542-4578-a44a-e60fdfb0d3ec/code-reuse-by-code-block",
                     status=HTTPStatus.OK,
                     json=load_response_json("code_reuse_block_report.json"))

            ci = CodeReuse()
            report = ci.get_code_blocks(TEST_HASH)

            self.assertEqual(len(report), 2527)
            self.assertEqual(
                len(list(filter(lambda x: x.is_common, report))), 1371)
            self.assertEqual(
                len(list(filter(lambda x: x.software_type == "malware", report))), 171)
