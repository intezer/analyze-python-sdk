#!/usr/bin/env python3

import argparse
import datetime
import io
import logging
import secrets
import time
import urllib.parse
from http import HTTPStatus
from typing import Optional
from typing import Tuple

import requests
import requests.adapters
from intezer_sdk import api
from intezer_sdk import errors
from intezer_sdk.analysis import Analysis
from intezer_sdk.util import get_note

_s1_session: Optional[requests.Session] = None
_logger = logging.getLogger('intezer')


class BaseUrlSession(requests.Session):
    base_url = None

    def __init__(self, base_url=None):
        if base_url:
            self.base_url = base_url
        super(BaseUrlSession, self).__init__()

    def request(self, method, url, *args, **kwargs):
        'Send the request after generating the complete URL.'
        url = self.create_url(url)
        return super(BaseUrlSession, self).request(
            method, url, *args, **kwargs
        )

    def prepare_request(self, request):
        'Prepare the request after generating the complete URL.'
        request.url = self.create_url(request.url)
        return super(BaseUrlSession, self).prepare_request(request)

    def create_url(self, url):
        'Create the URL based off this partial path.'
        return urllib.parse.urljoin(self.base_url, url)


def init_s1_requests_session(api_token: str, base_url: str, skip_ssl_verification: bool=True):
    headers = {'Authorization': 'ApiToken ' + api_token}
    global _s1_session
    _s1_session = BaseUrlSession(base_url)
    _s1_session.headers = headers
    _s1_session.verify = skip_ssl_verification
    _s1_session.mount('https://', requests.adapters.HTTPAdapter(max_retries=3))
    _s1_session.mount('http://', requests.adapters.HTTPAdapter(max_retries=3))


def analyze_by_file(threat_id: str):
    download_url, zipp_password = fetch_file(threat_id)
    file = download_file(download_url)
    analysis = Analysis(file_stream=file, file_name=f'{threat_id}.zip', zip_password=zipp_password)
    return analysis


def fetch_file(threat_id: str) -> Tuple[str, Optional[str]]:
    zip_password = secrets.token_urlsafe(32)
    fetch_file_time = datetime.datetime.utcnow() - datetime.timedelta(seconds=5)

    response = _s1_session.post('/web/api/v2.1/threats/fetch-file',
                                json={'data': {'password': zip_password}, 'filter': {'ids': [threat_id]}})
    assert_s1_response(response)

    for c in range(20):
        _logger.debug(f'starting to fetch file with request number {c}')
        time.sleep(10)
        response = _s1_session.get('/web/api/v2.1/activities',
                                   params={'threatIds': threat_id,
                                           'activityTypes': 86,
                                           'createdAt__gte': fetch_file_time.isoformat()})
        assert_s1_response(response)
        data = response.json()

        for activity in data['data']:
            download_url = activity['data'].get('downloadUrl')
            if download_url:
                return download_url, zip_password
    else:
        err_msg = 'Time out fetching the file, this is most likely when the endpoint is powered off' \
                  'or the agent is shut down'

        _logger.debug(err_msg)
        raise Exception(err_msg)


def download_file(download_url: str):
    _logger.debug(f'starting to download file from s1 with download url of {download_url}')
    response = _s1_session.get('/web/api/v2.1' + download_url)
    _logger.debug(f'got this response from s1 - {response}')

    assert_s1_response(response)
    _logger.debug(f'assert s1 response finished successfully')

    file = io.BytesIO(response.content)
    return file


def format_s1_error(error: dict) -> str:
    error_text = ''
    if 'title' in error:
        error_text = f'{error["title"]}'
    if 'details' in error:
        error_text = f'{error_text}: {error["details"]}'
    if 'code' in error:
        error_text = f'{error_text} (code:{error["code"]})'
    return error_text


def assert_s1_response(response: requests.Response):
    if response.status_code != HTTPStatus.OK:
        try:
            response_data = response.json()
            error_text = '\n'.join(format_s1_error(error) for error in response_data['errors'])
        except Exception:
            error_text = f'Server returned {response.status_code} status code'

        _logger.error(error_text)
        raise Exception(error_text)


def get_threat(threat_id: str):
    response = _s1_session.get('/web/api/v2.1/threats', params={'Ids': threat_id})
    assert_s1_response(response)
    return response.json()['data'][0]


def filter_threat(threat_info: dict) -> bool:
    return threat_info['agentDetectionInfo']['agentOsName'].lower().startswith(('linux', 'windows'))


def send_note(threat_id: str, analysis: Analysis, ignore_emojis: bool):
    options = {
        "ignore_emojis": ignore_emojis
    }
    note = get_note(analysis, options)
    response = _s1_session.post('/web/api/v2.1/threats/notes',
                                json={'data': {'text': note}, 'filter': {'ids': [threat_id]}})
    assert_s1_response(response)


def send_failure_note(note: str, threat_id: str):
    response = _s1_session.post('/web/api/v2.1/threats/notes',
                                json={'data': {'text': note}, 'filter': {'ids': [threat_id]}})
    assert_s1_response(response)


def analyze_threat(intezer_api_key: str, s1_api_key: str, s1_base_address: str, threat_id: str, skip_ssl_verification: bool=True, ignore_emojis: bool=False):
    api.set_global_api(intezer_api_key)
    init_s1_requests_session(s1_api_key, s1_base_address, skip_ssl_verification)
    _logger.info(f'incoming threat: {threat_id}')
    try:
        threat = get_threat(threat_id)
        if not filter_threat(threat):
            _logger.info(f'threat {threat_id} is been filtered')
            return

        threat_info = threat['threatInfo']
        file_hash = threat_info.get('sha256') or threat_info.get('sha1') or threat_info.get('md5')
        analysis = None
        if file_hash:
            _logger.debug(f'trying to analyze by hash {file_hash}')
            try:
                analysis = Analysis(file_hash=file_hash)
                analysis.send()
            except errors.HashDoesNotExistError:
                _logger.debug(f'hash {file_hash} not found on server, fetching the file from endpoint')
                analysis = None

        if not analysis:
            _logger.debug('starting to analyze file')
            analysis = analyze_by_file(threat_id)
            analysis.send(requester='s1')

        _logger.debug('waiting for analysis completion')
        analysis.wait_for_completion()
        _logger.debug('analysis completed')

        send_note(threat_id, analysis, ignore_emojis)
    except Exception as ex:
        send_failure_note(str(ex), threat_id)


def parse_argparse_args():
    parser = argparse.ArgumentParser(description='This script takes the threat file from SentinelOne threat '
                                                 'and analyze it in Intezer Analyze, the results will be '
                                                 'pushed to SentinelOne as a threat note.')

    parser.add_argument('-i', '--intezer-api-key', help='Intezer API key', required=True)
    parser.add_argument('-s', '--s1-api-key', help='S1 API Key', required=True)
    parser.add_argument('-a', '--s1-base-address', help='S1 base address', required=True)
    parser.add_argument('-t', '--threat-id', help='S1 threat id', required=True)
    parser.add_argument('-sv', '--skip-ssl-verification', action='store_false',
                        help='Skipping SSL verification on S1 request')
    parser.add_argument('-iem', '--ignore-emojis', action='store_true',
                        help='Ignore emojis on notes')

    return parser.parse_args()


if __name__ == '__main__':
    args = parse_argparse_args()

    analyze_threat(args.intezer_api_key,
                   args.s1_api_key,
                   args.s1_base_address,
                   args.threat_id,
                   args.skip_ssl_verification,
                   args.ignore_emojis)


