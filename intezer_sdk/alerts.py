import hashlib
import json
import time
import datetime
from io import BytesIO
from typing import Any
from typing import BinaryIO

import requests
from typing import Dict
from typing import List
from typing import Tuple
from typing import Union
from typing import Type
from typing import Optional

from intezer_sdk._api import IntezerApi
from intezer_sdk.alerts_results import AlertsHistoryResult
from intezer_sdk.analysis import FileAnalysis
from intezer_sdk.analysis import UrlAnalysis
from intezer_sdk.endpoint_analysis import EndpointAnalysis
from intezer_sdk.consts import AlertStatusCode
from intezer_sdk._api import IntezerApiClient
from intezer_sdk.api import get_global_api
from intezer_sdk import errors
from intezer_sdk import consts

DEFAULT_LIMIT = 100
DEFAULT_OFFSET = 0
ALERTS_SEARCH_REQUEST = '/alerts/search'


def get_alerts_by_alert_ids(alert_ids: List[str],
                            environments: List[str] = None,
                            api: IntezerApi = None) -> Tuple[int, List[dict]]:
    """
    Get alerts by alert ids.

    :param alert_ids: list of all ids to get alerts from.
    :param environments: what environments to get alerts from.
    :param api: The API connection to Intezer.
    :return: amount of alerts sent from server and list of alerts with all details about each alert.
    """
    api = IntezerApi(api or get_global_api())
    result = api.get_alerts_by_alert_ids(alert_ids, environments)
    return result['alerts_count'], result['alerts']


def generate_alerts_history_search_filters(*,
                                           start_time: datetime.datetime = None,
                                           end_time: datetime.datetime = None,
                                           environments: List[str] = None,
                                           offset: int = None,
                                           limit: int = None,
                                           sources: List[str] = None,
                                           risk_categories: List[str] = None,
                                           alert_verdicts: List[str] = None,
                                           family_names: List[str] = None,
                                           response_statuses: List[str] = None,
                                           hostnames: List[str] = None,
                                           free_text: str = None,
                                           site_name: str = None,
                                           account_name: str = None,
                                           exclude_alert_ids: List[str] = None,
                                           usernames: List[str] = None,
                                           file_hashes: List[str] = None,
                                           process_commandlines: List[str] = None,
                                           sort_by: List[str] = None,
                                           is_mitigated: bool = None,
                                           email_sender: str = None,
                                           email_recipient: str = None,
                                           email_subject: str = None,
                                           email_cc: str = None,
                                           email_bcc: str = None,
                                           email_message_id: str = None,
                                           email_reported_by: str = None,
                                           device_private_ips: List[str] = None,
                                           device_external_ips: List[str] = None,
                                           device_ids: List[str] = None,
                                           time_filter_type: List[str] = None,
                                           sort_order: str = None) -> Dict[str, Any]:
    filters = {}
    if start_time:
        filters['start_time'] = start_time.timestamp()
    if end_time:
        filters['end_time'] = end_time.timestamp()
    if environments:
        filters['environments'] = environments
    if offset is not None:
        filters['offset'] = offset
    if limit:
        filters['limit'] = limit
    if sources:
        filters['sources'] = sources
    if risk_categories:
        filters['risk_categories'] = risk_categories
    if alert_verdicts:
        filters['alert_verdicts'] = alert_verdicts
    if family_names:
        filters['family_names'] = family_names
    if response_statuses:
        filters['response_statuses'] = response_statuses
    if hostnames:
        filters['hostnames'] = hostnames
    if free_text:
        filters['free_text'] = free_text
    if site_name:
        filters['site_name'] = site_name
    if account_name:
        filters['account_name'] = account_name
    if exclude_alert_ids:
        filters['exclude_alert_ids'] = exclude_alert_ids
    if usernames:
        filters['usernames'] = usernames
    if file_hashes:
        filters['file_hashes'] = file_hashes
    if process_commandlines:
        filters['process_commandlines'] = process_commandlines
    if sort_by:
        filters['sort_by'] = sort_by
    if is_mitigated:
        filters['is_mitigated'] = is_mitigated
    if email_sender:
        filters['email_sender'] = email_sender
    if email_recipient:
        filters['email_recipient'] = email_recipient
    if email_subject:
        filters['email_subject'] = email_subject
    if email_cc:
        filters['email_cc'] = email_cc
    if email_bcc:
        filters['email_bcc'] = email_bcc
    if email_message_id:
        filters['email_message_id'] = email_message_id
    if email_reported_by:
        filters['email_reported_by'] = email_reported_by
    if device_private_ips:
        filters['device_private_ips'] = device_private_ips
    if device_external_ips:
        filters['device_external_ips'] = device_external_ips
    if device_ids:
        filters['device_ids'] = device_ids
    if time_filter_type:
        filters['time_filter_type'] = time_filter_type
    if sort_order:
        filters['sort_order'] = sort_order

    return filters


def query_alerts_history(*,
                         start_time: datetime.datetime = None,
                         end_time: datetime.datetime = None,
                         api: IntezerApiClient = None,
                         environments: List[str] = None,
                         offset: int = DEFAULT_OFFSET,
                         limit: int = DEFAULT_LIMIT,
                         sources: List[str] = None,
                         risk_categories: List[str] = None,
                         alert_verdicts: List[str] = None,
                         family_names: List[str] = None,
                         response_statuses: List[str] = None,
                         hostnames: List[str] = None,
                         free_text: str = None,
                         site_name: str = None,
                         account_name: str = None,
                         exclude_alert_ids: List[str] = None,
                         usernames: List[str] = None,
                         file_hashes: List[str] = None,
                         process_commandlines: List[str] = None,
                         sort_by: List[str] = None,
                         is_mitigated: bool = None,
                         email_sender: str = None,
                         email_recipient: str = None,
                         email_subject: str = None,
                         email_cc: str = None,
                         email_bcc: str = None,
                         email_message_id: str = None,
                         email_reported_by: str = None,
                         device_private_ips: List[str] = None,
                         device_external_ips: List[str] = None,
                         device_ids: List[str] = None,
                         time_filter_type: List[str] = None,
                         sort_order: str = None) -> AlertsHistoryResult:
    """
    Query for alerts history with query param.

    :param environments: Query alerts only from these environments.
    :param offset: Offset to start querying from - used for pagination.
    :param limit: Maximum number of alerts to return - used for pagination.
    :param start_time: Query alerts that were created after this timestamp (in UTC).
    :param end_time: Query alerts that were created before this timestamp (in UTC).
    :param api: Instance of Intezer API for request server.
    :param sources: Query alerts only with these sources (Valid source can be taken from AlertSource).
    :param risk_categories: Query alerts only with these risk categories.
    :param alert_verdicts: Query alerts only with these alert verdicts.
    :param family_names: Query alerts only with these family names.
    :param response_statuses: Query alerts only with these response statuses.
    :param hostnames: Query alerts only with these hostnames.
    :param free_text: Query alerts that contain this text in the following fields: family name, hostname, alert verdict.
    :param site_name: Query alerts only with this site name.
    :param account_name: Query alerts only with this account name.
    :param exclude_alert_ids: Query alerts that do not have these alert ids.
    :param usernames: Query alerts only with these usernames.
    :param file_hashes: Query alerts only with these file hashes.
    :param process_commandlines: Query alerts only with these process commandlines.
    :param sort_by: Sort alerts only with this sort_by_key value.
    :param is_mitigated: Query alerts only with this is_mitigated value.
    :param email_sender: Query alerts only with these email sender.
    :param email_recipient: Query alerts only with these email recipient.
    :param email_subject: Query alerts only with this email subject.
    :param email_cc: Sort alerts only with this email cc.
    :param email_bcc: Sort alerts only with this email bcc.
    :param email_message_id: Sort alerts only with this email message id.
    :param email_reported_by: Sort alerts only with this email reported by.
    :param device_private_ips: Query alerts only with these private ips.
    :param device_external_ips: Query alerts only with these external ips.
    :param device_ids: Query alerts only with these device ids.
    :param time_filter_type: The time value to filter alerts by.
    :param sort_order: The order to sort the alerts by.

    :return: Alert query result from server as Results iterator.
    """
    api = api or get_global_api()
    api.assert_any_on_premise()
    filters = generate_alerts_history_search_filters(
        start_time=start_time,
        end_time=end_time,
        environments=environments,
        offset=offset,
        limit=limit,
        sources=sources,
        risk_categories=risk_categories,
        alert_verdicts=alert_verdicts,
        family_names=family_names,
        response_statuses=response_statuses,
        hostnames=hostnames,
        free_text=free_text,
        site_name=site_name,
        account_name=account_name,
        exclude_alert_ids=exclude_alert_ids,
        usernames=usernames,
        file_hashes=file_hashes,
        process_commandlines=process_commandlines,
        sort_by=sort_by,
        is_mitigated=is_mitigated,
        email_sender=email_sender,
        email_recipient=email_recipient,
        email_subject=email_subject,
        email_cc=email_cc,
        email_bcc=email_bcc,
        email_message_id=email_message_id,
        email_reported_by=email_reported_by,
        device_private_ips=device_private_ips,
        device_external_ips=device_external_ips,
        device_ids=device_ids,
        time_filter_type=time_filter_type,
        sort_order=sort_order
    )

    return AlertsHistoryResult(ALERTS_SEARCH_REQUEST, api, filters)


class Alert:
    """
    The Alert class is used to represent an alert from the Intezer Analyze API.

    :ivar alert_id: The alert id.
    :vartype alert_id: str
    :ivar _report: The raw alert data.
    :vartype source: str
    :ivar verdict: The verdict of the alert.
    :vartype verdict: str
    :ivar family_name: The family name of the alert.
    :vartype family_name: str
    :ivar sender: The sender of the alert.
    :vartype sender: str
    :ivar intezer_alert_url: URL for the alert in Intezer's website.
    :vartype intezer_alert_url: str
    :ivar scans: Relevant scans for the alert.
    :vartype scans: list
    """

    def __init__(self,
                 alert_id: Optional[str] = None,
                 alert_stream: Optional[BinaryIO] = None,
                 api: IntezerApiClient = None):
        """
        Create a new Alert instance with the given alert id.
        Please note that this does not query the Intezer Analyze API for the alert data, but rather creates an Alert
        instance with the given alert id.

        :param alert_id: The alert id.
        :param api: The API connection to Intezer.
        """
        if alert_stream and alert_id:
            raise ValueError('Only one of alert_id and alert_stream should be provided')

        if not alert_stream and not alert_id:
            raise ValueError('One of alert_id and alert_stream should be provided')

        if alert_stream:
            if not bool(alert_stream.getvalue()):
                raise ValueError('alert_stream is empty')

            self.alert_id: str = self._parse_alert_id_from_alert_stream(alert_stream)
        else:
            self.alert_id: str = alert_id

        self._intezer_api_client = api
        self._api = IntezerApi(api or get_global_api())
        self._report: Optional[Dict] = None
        self.source: Optional[str] = None
        self.verdict: Optional[str] = None
        self.family_name: Optional[str] = None
        self.sender: Optional[str] = None
        self.intezer_alert_url: Optional[str] = None
        self.status: Optional[AlertStatusCode] = None
        self.scans: List[Union[UrlAnalysis, FileAnalysis, EndpointAnalysis]] = []

    @classmethod
    def _parse_alert_id_from_alert_stream(cls, alert_stream: BinaryIO) -> str:
        try:
            return hashlib.sha256(alert_stream.read()).hexdigest()
        finally:
            alert_stream.seek(0)

    def check_status(self) -> AlertStatusCode:
        """
        Refresh the alert data from the Intezer Analyze API - overrides current data (if exists) with the new data.

        :return: The updated status of the alert.

        """
        try:
            alert, status = self._api.get_alert_by_alert_id(alert_id=self.alert_id)
        except requests.HTTPError:
            self.status = AlertStatusCode.NOT_FOUND
            raise errors.AlertNotFoundError(self.alert_id)

        self._report = alert

        if status in (AlertStatusCode.IN_PROGRESS.value, AlertStatusCode.QUEUED.value):
            self.status = AlertStatusCode.IN_PROGRESS
            return self.status

        self.source = alert.get('source')
        self.verdict = alert.get('triage_result', {}).get('alert_verdict')
        self.family_name = alert.get('triage_result', {}).get('family_name')
        self.sender = alert.get('sender')
        self.intezer_alert_url = alert.get('intezer_alert_url')
        self.status = AlertStatusCode.FINISHED
        return self.status

    def is_running(self) -> bool:
        return self.status not in (AlertStatusCode.FINISHED, AlertStatusCode.NOT_FOUND)

    def result(self) -> dict:
        """
        Get the raw alert result, as received from Intezer Analyze API.

        :raises intezer_sdk.errors.AlertNotFound: If the alert was not found.
        :raises intezer_sdk.errors.AlertInProgressError: If the alert is in progress
        :return: The raw alert dictionary.
        """
        if self.status == AlertStatusCode.NOT_FOUND:
            raise errors.AlertNotFoundError(self.alert_id)
        if self.status == AlertStatusCode.IN_PROGRESS:
            raise errors.AlertInProgressError(self.alert_id)
        return self._report

    @classmethod
    def from_id(cls,
                alert_id: str,
                api: IntezerApiClient = None,
                fetch_scans: bool = False,
                wait: bool = False,
                timeout: Optional[int] = None):
        """
        Create a new Alert instance, and fetch the alert data from the Intezer Analyze API.

        :param alert_id: The alert id.
        :param api: The API connection to Intezer.
        :param fetch_scans: Whether to fetch the scans for the alert - this could take some time.
        :param wait: Wait for the alert to finish processing before returning.
        :param timeout: The timeout for the wait operation.
        :raises intezer_sdk.errors.AlertNotFound: If the alert was not found.
        :raises intezer_sdk.errors.AlertInProgressError: If the alert is still being processed.
        :return: The Alert instance, with the updated alert data.
        """
        new_alert = cls(alert_id=alert_id, api=api)
        status = new_alert.check_status()
        if status == AlertStatusCode.IN_PROGRESS:
            raise errors.AlertInProgressError(alert_id)
        if fetch_scans:
            new_alert.fetch_scans()
        if wait:
            new_alert.wait_for_completion(timeout=timeout)
        return new_alert

    @classmethod
    def send(cls,
             raw_alert: dict,
             alert_mapping: dict,
             source: str,
             api: IntezerApiClient = None,
             environment: Optional[str] = None,
             display_fields: Optional[List[str]] = None,
             default_verdict: Optional[str] = None,
             alert_sender: Optional[str] = None,
             wait: bool = False,
             timeout: Optional[int] = None,
             ):
        """
        Send an alert for further investigation using the Intezer Analyze API.

        :param raw_alert: The raw alert data.
        :param alert_mapping: The alert mapping - defines how to map the raw alert to get relevant information.
        :param source: The source of the alert.
        :param api: The API connection to Intezer.
        :param environment: The environment of the alert.
        :param display_fields: Fields from raw alert to display in the alert's webpage.
        :param default_verdict: The default verdict to send the alert with.
        :param alert_sender: The sender of the alert.
        :param wait: Wait for the alert to finish processing before returning.
        :param timeout: The timeout for the wait operation.
        :raises: :class:`requests.HTTPError` if the request failed for any reason.
        :return: The Alert instance, initialized with the alert id. when the `wait` parameter is set to True, the
                 resulting alert object will be initialized with the alert triage data.
        """
        _api = IntezerApi(api or get_global_api())
        send_alert_params = dict(
            alert=raw_alert,
            definition_mapping=alert_mapping,
            alert_source=source,
            environment=environment,
            display_fields=display_fields,
            default_verdict=default_verdict,
            alert_sender=alert_sender
        )

        send_alert_params = {key: value for key, value in send_alert_params.items() if value is not None}
        alert_id = _api.send_alert(**send_alert_params)

        alert = cls(alert_id=alert_id, api=api)
        if wait:
            alert.wait_for_completion(timeout=timeout)
        return alert

    @classmethod
    def send_phishing_email(cls,
                            raw_email: Optional[BinaryIO] = None,
                            api: Optional[IntezerApiClient] = None,
                            environment: Optional[str] = None,
                            default_verdict: Optional[str] = None,
                            alert_sender: Optional[str] = None,
                            wait: bool = False,
                            timeout: Optional[int] = None,
                            email_path: Optional[str] = None,
                            additional_info: Optional[dict] = None):
        """
        Send an alert for further investigation using the Intezer Analyze API.
        Should pass either raw_email or email_path.

        :param raw_email: The raw alert data.
        :param api: The API connection to Intezer.
        :param environment: The environment of the alert.
        :param default_verdict: The default verdict to send the alert with.
        :param alert_sender: The sender of the alert.
        :param wait: Wait for the alert to finish processing before returning.
        :param timeout: The timeout for the wait operation.
        :param email_path: The path to the email file.
        :param additional_info: Additional information to send with the alert.
        :raises: :class:`requests.HTTPError` if the request failed for any reason.
        :return: The Alert instance, initialized with the alert id. when the `wait` parameter is set to True, the
                 resulting alert object will be initialized with the alert triage data.
        """
        if not raw_email and not email_path:
            raise ValueError('raw_email or email_path must be provided')
        if email_path:
            with open(email_path, 'rb') as email_file:
                raw_email = BytesIO(email_file.read())
        _api = IntezerApi(api or get_global_api())
        if not bool(raw_email.getvalue()):
            raise ValueError('alert cannot be empty')

        send_alert_params = dict(
            alert=raw_email,
            file_name=cls._parse_alert_id_from_alert_stream(raw_email),
            alert_source='phishing_emails',
            environment=environment,
            display_fields=','.join(['reported_by', 'sender', 'received', 'subject', 'message_id', 'to']),
            default_verdict=default_verdict,
            alert_sender=alert_sender,
            additional_info=json.dumps(additional_info) if additional_info else None,
        )

        send_alert_params = {key: value for key, value in send_alert_params.items() if value is not None}
        alert_id = _api.send_binary_alert(**send_alert_params)

        alert = cls(alert_id=alert_id, api=api)
        if wait:
            alert.wait_for_completion(timeout=timeout)
        return alert

    def wait_for_completion(self,
                            interval: int = None,
                            sleep_before_first_check=False,
                            timeout: Optional[datetime.timedelta] = None):
        """
        Blocks until the alert is finished processing, or until the timeout is reached.

        :param interval: The interval to wait between checks in seconds.
        :param sleep_before_first_check: Whether to sleep before the first status check.
        :param timeout: Maximum duration to wait for analysis completion in seconds.
        :raises intezer_sdk.errors.AlertNotFoundError: If the alert was not found.
        :raise TimeoutError: If the timeout was reached.
        """
        start_time = datetime.datetime.utcnow()
        if not interval:
            interval = consts.CHECK_STATUS_INTERVAL

        if self.is_running:
            if sleep_before_first_check:
                time.sleep(interval)
            status_code: AlertStatusCode = self.check_status()

            while status_code != AlertStatusCode.FINISHED:
                timeout_passed = timeout and datetime.datetime.utcnow() - start_time > timeout
                if timeout_passed:
                    raise TimeoutError()
                time.sleep(interval)
                status_code = self.check_status()

    def fetch_scans(self):
        """
        Fetch the scans of the alert.
        """
        if self.status == AlertStatusCode.NOT_FOUND:
            raise errors.AlertNotFoundError(self.alert_id)
        elif self.status == AlertStatusCode.IN_PROGRESS:
            raise errors.AlertInProgressError(self.alert_id)

        def _fetch_scan(scan_: dict,
                        scan_key: str,
                        scan_object: Union[Type[FileAnalysis], Type[EndpointAnalysis], Type[UrlAnalysis]]):
            current_analysis_id = scan_.get(scan_key, {}).get('analysis_id')
            if current_analysis_id:
                self.scans.append(scan_object.from_analysis_id(analysis_id=current_analysis_id,
                                                               api=self._intezer_api_client))

        self.scans = []
        for scan in self._report.get('scans', []):
            scan_type = scan.get('scan_type')
            if scan_type == 'file':
                _fetch_scan(scan, 'file_analysis', FileAnalysis)
            elif scan_type == 'endpoint':
                _fetch_scan(scan, 'endpoint_analysis', EndpointAnalysis)
            elif scan_type == 'url':
                _fetch_scan(scan, 'url_analysis', UrlAnalysis)
