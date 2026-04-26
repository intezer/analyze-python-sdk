from typing import Any

from requests import HTTPError

from intezer_sdk import errors
from intezer_sdk._api import IntezerApi
from intezer_sdk._api import IntezerApiClient
from intezer_sdk.api import get_global_api
from intezer_sdk.cases_results import CasesHistoryResult
from intezer_sdk.util import add_filter

DEFAULT_LIMIT = 100
DEFAULT_OFFSET = 0
CASES_SEARCH_REQUEST = '/cases/search'


def generate_cases_search_filters(*,
                                  case_ids: list[str] = None,
                                  exclude_case_ids: list[str] = None,
                                  time_range_start: int = None,
                                  time_range_end: int = None,
                                  time_range_field: str = None,
                                  sources: list[str] = None,
                                  free_text: str = None,
                                  sub_tenant_names: list[str] = None,
                                  devices: dict = None,
                                  users: dict = None,
                                  alert_identifiers: list[dict] = None,
                                  risk_categories: list[str] = None,
                                  case_verdicts: list[str] = None,
                                  response_statuses: list[str] = None,
                                  case_statuses: list[str] = None,
                                  assigned_account_ids: list[str] = None,
                                  priorities: list[str] = None,
                                  external_ticket_vendors: list[str] = None,
                                  analyst_verdicts: list[str] = None,
                                  offset: int = None,
                                  limit: int = None,
                                  search_mode: str = None,
                                  sort_by: str = None) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    add_filter(payload, 'case_ids', case_ids)
    add_filter(payload, 'exclude_case_ids', exclude_case_ids)
    add_filter(payload, 'time_range_start', time_range_start)
    add_filter(payload, 'time_range_end', time_range_end)
    add_filter(payload, 'time_range_field', time_range_field)
    add_filter(payload, 'sources', sources)
    add_filter(payload, 'free_text', free_text)
    add_filter(payload, 'sub_tenant_names', sub_tenant_names)
    add_filter(payload, 'devices', devices)
    add_filter(payload, 'users', users)
    add_filter(payload, 'alert_identifiers', alert_identifiers)
    add_filter(payload, 'risk_categories', risk_categories)
    add_filter(payload, 'case_verdicts', case_verdicts)
    add_filter(payload, 'response_statuses', response_statuses)
    add_filter(payload, 'case_statuses', case_statuses)
    add_filter(payload, 'assigned_account_ids', assigned_account_ids)
    add_filter(payload, 'priorities', priorities)
    add_filter(payload, 'external_ticket_vendors', external_ticket_vendors)
    add_filter(payload, 'analyst_verdicts', analyst_verdicts)

    filters: dict[str, Any] = {'payload': payload}
    add_filter(filters, 'offset', offset)
    add_filter(filters, 'limit', limit)
    add_filter(filters, 'search_mode', search_mode)
    add_filter(filters, 'sort_by', sort_by)

    return filters


def query_cases_history(*,
                        api: IntezerApiClient = None,
                        case_ids: list[str] = None,
                        exclude_case_ids: list[str] = None,
                        time_range_start: int = None,
                        time_range_end: int = None,
                        time_range_field: str = None,
                        sources: list[str] = None,
                        free_text: str = None,
                        sub_tenant_names: list[str] = None,
                        devices: dict = None,
                        users: dict = None,
                        alert_identifiers: list[dict] = None,
                        risk_categories: list[str] = None,
                        case_verdicts: list[str] = None,
                        response_statuses: list[str] = None,
                        case_statuses: list[str] = None,
                        assigned_account_ids: list[str] = None,
                        priorities: list[str] = None,
                        external_ticket_vendors: list[str] = None,
                        analyst_verdicts: list[str] = None,
                        offset: int = DEFAULT_OFFSET,
                        limit: int = DEFAULT_LIMIT,
                        search_mode: str = None,
                        sort_by: str = None) -> CasesHistoryResult:
    """
    Query for cases with query params.

    :param api: Instance of Intezer API for request server.
    :param case_ids: Query only these case ids.
    :param exclude_case_ids: Query cases that do not have these case ids.
    :param time_range_start: Start of time range (Unix timestamp in seconds).
    :param time_range_end: End of time range (Unix timestamp in seconds).
    :param time_range_field: Field to apply the time range on (creation_time / modification_time / last_attached_alert_time).
    :param sources: Query cases only with these sources.
    :param free_text: Free text used to search across title, case id, devices and assigned accounts.
    :param sub_tenant_names: Query cases only with these sub tenant names.
    :param devices: Filters related to devices involved in the case (hostnames, device_private_ips, device_external_ips, device_ids, device_tags, device_managed_by, device_keys, source_device_keys, target_device_keys).
    :param users: Filters related to users involved in the case (user_ids, user_emails, user_names, user_sids, user_keys).
    :param alert_identifiers: Query cases only with these alert identifiers (list of {alert_id, environment}).
    :param risk_categories: Query cases only with these risk categories.
    :param case_verdicts: Query cases only with these case verdicts.
    :param response_statuses: Query cases only with these response statuses.
    :param case_statuses: Query cases only with these case statuses (suppressed / new / in_progress / on_hold / closed).
    :param assigned_account_ids: Query cases only with these assigned account ids.
    :param priorities: Query cases only with these priorities (informational / low / medium / high / escalated).
    :param external_ticket_vendors: Query cases only with these external ticket vendors.
    :param analyst_verdicts: Query cases only with these analyst verdicts.
    :param offset: Offset to start querying from - used for pagination.
    :param limit: Maximum number of cases to return - used for pagination.
    :param search_mode: How multiple filters are combined (and / or).
    :param sort_by: Sorting field for the results (creation_time / alerts_count / modification_time / last_attached_alert_time).

    :return: Case query result from server as Results iterator.
    """
    api = api or get_global_api()
    filters = generate_cases_search_filters(
        case_ids=case_ids,
        exclude_case_ids=exclude_case_ids,
        time_range_start=time_range_start,
        time_range_end=time_range_end,
        time_range_field=time_range_field,
        sources=sources,
        free_text=free_text,
        sub_tenant_names=sub_tenant_names,
        devices=devices,
        users=users,
        alert_identifiers=alert_identifiers,
        risk_categories=risk_categories,
        case_verdicts=case_verdicts,
        response_statuses=response_statuses,
        case_statuses=case_statuses,
        assigned_account_ids=assigned_account_ids,
        priorities=priorities,
        external_ticket_vendors=external_ticket_vendors,
        analyst_verdicts=analyst_verdicts,
        offset=offset,
        limit=limit,
        search_mode=search_mode,
        sort_by=sort_by,
    )

    return CasesHistoryResult(CASES_SEARCH_REQUEST, api, filters)


class Case:
    """
    The Case class is used to represent a case from the Intezer Platform API.

    :ivar case_id: The case id.
    :vartype case_id: str
    :ivar case_title: The case title.
    :vartype case_title: str
    :ivar case_status: The current status of the case.
    :vartype case_status: str
    :ivar case_priority: The current priority of the case.
    :vartype case_priority: str
    :ivar alerts_count: Number of alerts attached to the case.
    :vartype alerts_count: int
    :ivar risk_category: The risk category calculated for the case.
    :vartype risk_category: str
    :ivar case_verdict: The verdict assigned to the case by triage.
    :vartype case_verdict: str
    :ivar response_status: The response status of the case triage.
    :vartype response_status: str
    :ivar analyst_verdict: The analyst verdict on the case.
    :vartype analyst_verdict: str
    :ivar intezer_case_url: URL for the case in Intezer's website.
    :vartype intezer_case_url: str
    """

    def __init__(self,
                 case_id: str,
                 api: IntezerApiClient = None):
        """
        Create a new Case instance with the given case id.
        Please note that this does not query the Intezer Platform API for the case data, but rather creates a Case
        instance with the given case id.

        If you wish to fetch the case data from the Intezer Platform API, use the `from_id` class method.

        :param case_id: The case id.
        :param api: The API connection to Intezer.
        """
        self.case_id = case_id
        self._intezer_api_client = api
        self._api = IntezerApi(api or get_global_api())
        self._result: dict | None = None
        self.case_title: str | None = None
        self.case_status: str | None = None
        self.case_priority: str | None = None
        self.alerts_count: int | None = None
        self.case_sources: list[str] | None = None
        self.case_tags: list[str] | None = None
        self.risk_category: str | None = None
        self.case_verdict: str | None = None
        self.response_status: str | None = None
        self.analyst_verdict: str | None = None
        self.intezer_case_url: str | None = None

    def fetch_info(self):
        """
        Fetch the case data from the Intezer Platform API.

        :raises intezer_sdk.errors.CaseNotFoundError: If the case was not found.
        """
        try:
            self._result = self._api.get_case_by_id(self.case_id)
        except HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                raise errors.CaseNotFoundError(self.case_id)
            raise

        self.case_title = self._result.get('case_title')
        self.case_status = self._result.get('case_status')
        self.case_priority = self._result.get('case_priority')
        self.alerts_count = self._result.get('alerts_count')
        self.case_sources = self._result.get('case_sources')
        self.case_tags = self._result.get('case_tags')
        self.analyst_verdict = self._result.get('analyst_verdict')
        self.intezer_case_url = self._result.get('intezer_case_url')

        case_triage = self._result.get('case_triage') or {}
        self.risk_category = case_triage.get('risk_category')
        self.case_verdict = case_triage.get('case_verdict')
        self.response_status = case_triage.get('response_status')

    def result(self) -> dict | None:
        """
        Get the raw case result, as received from Intezer Platform API.

        :return: The raw case dictionary.
        """
        return self._result

    @classmethod
    def from_id(cls, case_id: str, api: IntezerApiClient = None) -> 'Case':
        """
        Create a new Case instance, and fetch the case data from the Intezer Platform API.

        :param case_id: The case id.
        :param api: The API connection to Intezer.
        :raises intezer_sdk.errors.CaseNotFoundError: If the case was not found.
        :return: The Case instance, with the updated case data.
        """
        new_case = cls(case_id=case_id, api=api)
        new_case.fetch_info()
        return new_case

    def get_devices(self) -> list[dict]:
        """
        Get the devices related to this case.

        :return: The list of devices related to the case.
        """
        if not self.case_id:
            raise ValueError('Case ID is required to get case devices.')

        result = self._api.get_case_devices(self.case_id)
        return result.get('devices', [])

    def get_users(self) -> list[dict]:
        """
        Get the users related to this case.

        :return: The list of users related to the case.
        """
        if not self.case_id:
            raise ValueError('Case ID is required to get case users.')

        result = self._api.get_case_users(self.case_id)
        return result.get('users', [])

    def get_ttps(self) -> list[dict]:
        """
        Get the TTPs related to this case.

        :return: The list of TTPs related to the case.
        """
        if not self.case_id:
            raise ValueError('Case ID is required to get case TTPs.')

        result = self._api.get_case_ttps(self.case_id)
        return result.get('ttps', [])
