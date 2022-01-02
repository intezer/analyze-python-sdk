import argparse
import collections
import datetime
import io
import logging
import secrets
import time
import urllib.parse
from http import HTTPStatus
from typing import List
from typing import Optional
from typing import Tuple

import requests
import requests.adapters
from intezer_sdk import api
from intezer_sdk import errors
from intezer_sdk.analysis import Analysis

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


def init_s1_requests_session(api_token: str, base_url: str, verify: bool=False):
    headers = {'Authorization': 'ApiToken ' + api_token}
    global _s1_session
    _s1_session = BaseUrlSession(base_url)
    _s1_session.headers = headers
    # _s1_session.verify = verify # TODO
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


def get_analysis_family(analysis: Analysis, software_type_priorities: List[str]) -> Tuple[Optional[str], Optional[int]]:
    result = analysis.result()
    family_name = result.get('family_name')
    if family_name:
        reused_gene_count = get_analysis_family_by_family_id(analysis, result['family_id'])
        return family_name, reused_gene_count

    largest_family_by_software_type = find_largest_family(analysis)
    for software_type in software_type_priorities:
        if software_type in largest_family_by_software_type:
            family = largest_family_by_software_type[software_type]
            return family['family_name'], family['reused_gene_count']

    return None, None


def get_analysis_family_by_family_id(analysis: Analysis, family_id: str) -> Optional[int]:
    reused_gene_count = None
    for sub_analysis in analysis.get_sub_analyses():
        if not sub_analysis.code_reuse:
            continue
        for family in sub_analysis.code_reuse['families']:
            if family['family_id'] == family_id:
                reused_gene_count = family['reused_gene_count']
        if reused_gene_count:
            break
    return reused_gene_count


def find_largest_family(analysis: Analysis) -> dict:
    largest_family_by_software_type = collections.defaultdict(lambda: {'reused_gene_count': 0})
    for sub_analysis in analysis.get_sub_analyses():
        for family in sub_analysis.code_reuse['families']:
            software_type = family['software_type']
            if family['reused_gene_count'] > largest_family_by_software_type[software_type]['reused_gene_count']:
                largest_family_by_software_type[software_type] = family
    return largest_family_by_software_type


def human_readable_size(num: int) -> str:
    for unit in ['', 'KB', 'MB', 'GB']:
        if abs(num) < 1024.0:
            return f'{num:3.1f}{unit}'
        num /= 1024.0
    return f'{num:.1f}GB'


def get_note(analysis: Analysis) -> str:
    result = analysis.result()

    metadata = analysis.get_root_analysis().metadata
    verdict = result['verdict'].lower()
    sub_verdict = result['sub_verdict'].lower()

    note = (f'Intezer Analyze File Scan\n'
            f'=========================\n\n')

    if verdict == 'malicious':
        emoji = '🧨'
        main_family, gene_count = get_analysis_family(analysis, ['malware', 'malicious_packer'])
    elif verdict == 'trusted':
        emoji = '🟢'
        main_family, gene_count = get_analysis_family(analysis, ['application', 'library', 'interpreter', 'installer'])
    elif verdict == 'suspicious':
        emoji = '⚠'
        main_family, gene_count = get_analysis_family(analysis, ['administration_tool', 'packer'])
    else:
        emoji = '❔'
        main_family = None
        gene_count = None

    note = f'{note}{emoji} {verdict.capitalize()}'

    if main_family:
        note = f'{note} - {main_family}'
        if gene_count:
            note = f'{note} ({gene_count} shared code genes)'
    note = f'{note}\n\nSize: {human_readable_size(metadata["size_in_bytes"])}\n'
    if 'file_type' in metadata:
        note = f'{note}File type: {metadata["file_type"]}\n'
    if verdict == 'malicious':
        iocs = len(analysis.iocs['files']) + len(analysis.iocs['network']) - 1

        if iocs:
            note = f'{note}IOCs: {iocs} IOCs\n'
        dynamic_ttps = len(analysis.dynamic_ttps)

        if dynamic_ttps:
            note = f'{note}TTPs: {dynamic_ttps} techniques\n'

    elif verdict == 'suspicious' or verdict == 'unknown':
        note = f'{note}{verdict} - {sub_verdict}\n'

    note = (f'{note}\nFull report\n'
            f'👉{result["analysis_url"]}')

    return note


def send_note(threat_id: str, analysis: Analysis):
    note = get_note(analysis)
    response = _s1_session.post('/web/api/v2.1/threats/notes',
                                json={'data': {'text': note}, 'filter': {'ids': [threat_id]}})
    assert_s1_response(response)


def send_failure_note(note: str, threat_id: str):
    response = _s1_session.post('/web/api/v2.1/threats/notes',
                                json={'data': {'text': note}, 'filter': {'ids': [threat_id]}})
    assert_s1_response(response)


def analyze_threat(intezer_api_key: str, s1_api_key: str, s1_base_address: str, threat_id: str, verify: bool=False):
    api.set_global_api(intezer_api_key)
    init_s1_requests_session(s1_api_key, s1_base_address, verify)
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

        send_note(threat_id, analysis)
    except Exception as ex:
        send_failure_note(str(ex), threat_id)


def parse_argparse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('-i', '--intezer-api-key', help='Pass intezer API key', dest='intezer_api_key', required=True)
    parser.add_argument('-s', '--s1', help='Pass S1 API Key', dest='s1_api_key', required=True)
    parser.add_argument('-u', '--url', help='Pass S1 base address', dest='s1_base_address', required=True)
    parser.add_argument('-t', '--threat', help='Pass threat id', dest='threat_id', required=True)
    parser.add_argument('-v', '--verify', help='Pass verify flag to s1 request', dest='verify', default=False)

    return parser.parse_args()


if __name__ == '__main__':
    '''
    The purpose of the script is to extract an analysis from s1 account and analyze it using Intezer analyze.
    The script generate a note that represents the analysis done by Intezer and sends the note to S1 
    
    The script takes 4 command arguments, usage e.g:
    python3 $PATH/s1_generic.py \
        -i $INTEZER_API_KEY \
        -s $S1_API_KEY \
        -u $S1_ADDRESS \
        -t $THREAT_ID
    '''
    args = parse_argparse_args()

    analyze_threat(args.intezer_api_key,
                   args.s1_api_key,
                   args.s1_base_address,
                   args.threat_id,
                   args.verify)

