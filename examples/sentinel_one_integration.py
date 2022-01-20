#!/usr/bin/env python3

import argparse
import datetime
import io
import logging
import logging.handlers
import secrets
import sys
import time
import urllib.parse
from http import HTTPStatus
from typing import Optional
from typing import Tuple

import requests
import requests.adapters

from intezer_sdk import api
from intezer_sdk import errors
from intezer_sdk import util
from intezer_sdk.analysis import Analysis

_s1_session: Optional[requests.Session] = None
_logger = logging.getLogger('intezer')


class BaseUrlSession(requests.Session):
    """Taken from https://github.com/requests/toolbelt/blob/master/requests_toolbelt/sessions.py"""
    base_url = None

    def __init__(self, base_url=None):
        if base_url:
            self.base_url = base_url
        super(BaseUrlSession, self).__init__()

    def request(self, method, url, *args, **kwargs):
        """Send the request after generating the complete URL."""
        url = self.create_url(url)
        return super(BaseUrlSession, self).request(
            method, url, *args, **kwargs
        )

    def prepare_request(self, request):
        """Prepare the request after generating the complete URL."""
        request.url = self.create_url(request.url)
        return super(BaseUrlSession, self).prepare_request(request)

    def create_url(self, url):
        """Create the URL based off this partial path."""
        return urllib.parse.urljoin(self.base_url, url)


def init_s1_requests_session(api_token: str, base_url: str, skip_ssl_verification: bool):
    headers = {'Authorization': 'ApiToken ' + api_token}
    global _s1_session
    _s1_session = BaseUrlSession(base_url)
    _s1_session.headers = headers
    _s1_session.verify = not skip_ssl_verification
    _s1_session.mount('https://', requests.adapters.HTTPAdapter(max_retries=3))
    _s1_session.mount('http://', requests.adapters.HTTPAdapter(max_retries=3))


def analyze_by_file(threat_id: str):
    download_url, zipp_password = fetch_file(threat_id)
    file = download_file(download_url)
    _logger.debug('starting to analyze file')
    analysis = Analysis(file_stream=file, file_name=f'{threat_id}.zip', zip_password=zipp_password)
    return analysis


def fetch_file(threat_id: str) -> Tuple[str, Optional[str]]:
    zip_password = secrets.token_urlsafe(32)
    fetch_file_time = datetime.datetime.utcnow() - datetime.timedelta(seconds=5)

    _logger.debug('sending fetch command to the endpoint')
    response = _s1_session.post('/web/api/v2.1/threats/fetch-file',
                                json={'data': {'password': zip_password}, 'filter': {'ids': [threat_id]}})
    assert_s1_response(response)

    for count in range(20):
        _logger.debug(f'waiting for s1 to fetch the file from the endpoint ({count})')
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
        err_msg = ('Time out fetching the file, this is most likely when the endpoint is powered off'
                   'or the agent is shut down')

        _logger.debug(err_msg)
        raise Exception(err_msg)


def download_file(download_url: str):
    _logger.debug(f'downloading file from s1 (download url of {download_url})')
    response = _s1_session.get('/web/api/v2.1' + download_url)
    assert_s1_response(response)
    _logger.debug(f'download finished')

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


def send_note(threat_id: str, analysis: Analysis):
    note = util.get_analysis_summary(analysis)

    response = _s1_session.post('/web/api/v2.1/threats/notes',
                                json={'data': {'text': note}, 'filter': {'ids': [threat_id]}})
    assert_s1_response(response)
    _logger.info('note sent')


def send_failure_note(note: str, threat_id: str):
    note = f'Intezer Analyze File Scan failed: {note}'
    response = _s1_session.post('/web/api/v2.1/threats/notes',
                                json={'data': {'text': note}, 'filter': {'ids': [threat_id]}})
    assert_s1_response(response)


def analyze_threat(threat_id: str, threat: dict = None):
    _logger.info(f'incoming threat: {threat_id}')
    try:
        if not threat:
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
            analysis = analyze_by_file(threat_id)
            analysis.send(requester='s1')

        _logger.debug('waiting for analysis completion')
        analysis.wait_for_completion()
        _logger.debug('analysis completed')

        send_note(threat_id, analysis)
    except Exception as ex:
        _logger.exception(f'failed to process threat {threat_id}')
        send_failure_note(str(ex), threat_id)


def parse_argparse_args():
    parser = argparse.ArgumentParser(description='This script takes the threat file from SentinelOne threat '
                                                 'and analyze it in Intezer Analyze, the results will be '
                                                 'pushed to SentinelOne as a threat note.')

    parser.add_argument('-i', '--intezer-api-key', help='Intezer API key', required=True)
    parser.add_argument('-s', '--s1-api-key', help='S1 API Key', required=True)
    parser.add_argument('-a', '--s1-base-address', help='S1 base address', required=True)
    parser.add_argument('-sv', '--skip-ssl-verification', action='store_true',
                        help='Skipping SSL verification on S1 request')
    subparser_options = {}
    if sys.version_info >= (3, 7):
        subparser_options['required'] = True

    subparsers = parser.add_subparsers(title='valid subcommands', dest='subcommand', **subparser_options)
    threat_parser = subparsers.add_parser('threat', help='Get a threat ID and analyze it')
    threat_parser.add_argument('threat_id', help='SentinelOne threat id')
    query_parser = subparsers.add_parser('query', help='Analyze new incoming threat')
    query_parser.add_argument('--since',
                              help='query threats from certain date in the format YYYY-MM-DD',
                              type=lambda s: datetime.datetime.strptime(s, '%Y-%m-%d'),)

    return parser.parse_args()


def _init_logger():
    _logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
    _logger.addHandler(handler)


def query_threats(next_time_query: Optional[datetime.datetime]):
    next_time_query = next_time_query or datetime.datetime.utcnow()
    while True:
        _logger.info('checking for new threats...')
        response = _s1_session.get('/web/api/v2.1/threats', params={'createdAt__gte': next_time_query.isoformat()})
        next_time_query = datetime.datetime.utcnow()
        assert_s1_response(response)
        threats = response.json()['data']
        for threat in threats:
            analyze_threat(threat['id'], threat)

        if not threats:
            _logger.info('no new threats found')
            time.sleep(10)


if __name__ == '__main__':
    _args = parse_argparse_args()
    api.set_global_api(_args.intezer_api_key)
    init_s1_requests_session(_args.s1_api_key, _args.s1_base_address, _args.skip_ssl_verification)
    _init_logger()
    if _args.subcommand == 'threat':
        analyze_threat(_args.threat_id)
    elif _args.subcommand == 'query':
        query_threats(_args.since)
    else:
        print('error: the following arguments are required: subcommand')
        sys.exit(1)
