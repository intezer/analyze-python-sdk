import datetime
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from requests import HTTPError

from intezer_sdk import errors
from intezer_sdk._api import IntezerApi
from intezer_sdk._api import IntezerApiClient
from intezer_sdk.api import get_global_api
from intezer_sdk.incidents_results import IncidentsHistoryResult
from intezer_sdk.util import add_filter


DEFAULT_LIMIT = 100
DEFAULT_OFFSET = 0
INCIDENTS_SEARCH_REQUEST = '/incidents/search'


def generate_incidents_history_search_filters(*,
                                              incident_ids: List[str] = None,
                                              environments: List[str] = None,
                                              offset: int = None,
                                              limit: int = None,
                                              time_filter_type: List[str] = None,
                                              start_time: datetime.datetime = None,
                                              end_time: datetime.datetime = None,
                                              sources: List[str] = None,
                                              senders: List[str] = None,
                                              severities: List[str] = None,
                                              statuses: List[str] = None,
                                              names: List[str] = None,
                                              related_alert_ids: List[str] = None,
                                              risk_categories: List[str] = None,
                                              response_statuses: List[str] = None,
                                              free_text: str = None,
                                              sort_by: List[str] = None,
                                              sort_order: str = None,
                                              include_raw_incident: bool = None) -> Dict[str, Any]:
    filters = {}
    start_timestamp = int(start_time.timestamp()) if start_time else None
    end_timestamp = int(end_time.timestamp()) if end_time else None

    add_filter(filters, 'incident_ids', incident_ids)
    add_filter(filters, 'environments', environments)
    add_filter(filters, 'offset', offset)
    add_filter(filters, 'limit', limit)
    add_filter(filters, 'time_filter_type', time_filter_type)
    add_filter(filters, 'start_time', start_timestamp)
    add_filter(filters, 'end_time', end_timestamp)
    add_filter(filters, 'sources', sources)
    add_filter(filters, 'senders', senders)
    add_filter(filters, 'severities', severities)
    add_filter(filters, 'statuses', statuses)
    add_filter(filters, 'names', names)
    add_filter(filters, 'related_alert_ids', related_alert_ids)
    add_filter(filters, 'risk_categories', risk_categories)
    add_filter(filters, 'response_statuses', response_statuses)
    add_filter(filters, 'free_text', free_text)
    add_filter(filters, 'sort_by', sort_by)
    add_filter(filters, 'sort_order', sort_order)
    add_filter(filters, 'include_raw_incident', include_raw_incident)

    return filters


def query_incidents_history(*,
                            api: IntezerApiClient = None,
                            incident_ids: List[str] = None,
                            environments: List[str] = None,
                            offset: int = DEFAULT_OFFSET,
                            limit: int = DEFAULT_LIMIT,
                            time_filter_type: List[str] = None,
                            start_time: datetime.datetime = None,
                            end_time: datetime.datetime = None,
                            sources: List[str] = None,
                            senders: List[str] = None,
                            severities: List[str] = None,
                            statuses: List[str] = None,
                            names: List[str] = None,
                            related_alert_ids: List[str] = None,
                            risk_categories: List[str] = None,
                            response_statuses: List[str] = None,
                            free_text: str = None,
                            sort_by: List[str] = None,
                            sort_order: str = None,
                            include_raw_incident: bool = None) -> IncidentsHistoryResult:
    """
    Query for incidents history with query param.

    :param api: Instance of Intezer API for request server.
    :param incident_ids: Query only this incident ids.
    :param environments: Query incidents only from these environments.
    :param offset: Offset to start querying from - used for pagination.
    :param limit: Maximum number of incidents to return - used for pagination.
    :param time_filter_type: The time value to filter incidents by (creation_time / received_time / triage_time / triage_change_time / triage_or_triage_change_time).
    :param start_time: Query incidents that were created after this timestamp (in UTC).
    :param end_time: Query incidents that were created before this timestamp (in UTC).
    :param sources: Query incidents only with these sources.
    :param senders: Query incidents only with these senders.
    :param severities: Query incidents only with these severities.
    :param statuses: Query incidents only with these statuses.
    :param names: Query incidents only with these names.
    :param related_alert_ids: Query incidents only with these related alert ids.
    :param risk_categories: Query incidents only with these risk categories.
    :param response_statuses: Query incidents only with these response statuses.
    :param free_text: Query incidents that contain this text in the following fields: name, severity, status, related_alert_ids.
    :param sort_by: Sort incidents only with this sort_by_key value (creation_time / received_time / triage_time / triage_change_time / risk_score).
    :param sort_order: The order to sort the incidents by (asc / desc).
    :param include_raw_incident: Include the raw incident data in the results.

    :return: Incident query result from server as Results iterator.
    """
    api = api or get_global_api()
    api.assert_any_on_premise()
    filters = generate_incidents_history_search_filters(
        incident_ids=incident_ids,
        environments=environments,
        offset=offset,
        limit=limit,
        time_filter_type=time_filter_type,
        start_time=start_time,
        end_time=end_time,
        sources=sources,
        senders=senders,
        severities=severities,
        statuses=statuses,
        names=names,
        related_alert_ids=related_alert_ids,
        risk_categories=risk_categories,
        response_statuses=response_statuses,
        free_text=free_text,
        sort_by=sort_by,
        sort_order=sort_order,
        include_raw_incident=include_raw_incident,
    )

    return IncidentsHistoryResult(INCIDENTS_SEARCH_REQUEST, api, filters)


class Incident:
    """
    The Incident class is used to represent an incident from the Intezer API.

    :ivar incident_id: The incident id.
    :vartype incident_id: str
    :ivar name: The incident name.
    :vartype name: str
    :ivar source: The source of the incident.
    :vartype source: str
    :ivar sender: The sender of the incident.
    :vartype sender: str
    :ivar risk_category: The risk_category of the incident.
    :vartype risk_category: str
    :ivar risk_level: The risk_level of the incident. Can be one of 'informational', 'low', 'medium', 'high', 'critical'.
    :ivar intezer_incident_url: URL for the incident in Intezer's website.
    :vartype intezer_incident_url: str
    """

    def __init__(
        self,
        incident_id: Optional[str] = None,
        environment: Optional[str] = None,
        api: IntezerApiClient = None,
    ):
        """
        Create a new Incident instance with the given incident id.
        Please note that this does not query the Intezer Analyze API for the incident data, but rather creates an Incident
        instance with the given incident id.

        If you wish to fetch the incident data from the Intezer Analyze API, use the `from_id` class method.

        :param incident_id: The incident id.
        :param environment: The environment of the incident.
        :param api: The API connection to Intezer.
        """
        self.incident_id = incident_id
        self.environment = environment
        self._intezer_api_client = api
        self._api = IntezerApi(api or get_global_api())
        self._result: Optional[Dict] = None
        self.name: Optional[str] = None
        self.source: Optional[str] = None
        self.sender: Optional[str] = None
        self.risk_category: Optional[str] = None
        self.risk_level: Optional[str] = None
        self.intezer_incident_url: Optional[str] = None

    def fetch_info(self):
        """
        Fetch the incident data from the Intezer Analyze API.

        :raises intezer_sdk.errors.IncidentNotFound: If the incident was not found.
        """
        if not self.incident_id:
            raise ValueError("Incident ID is required to fetch incident info.")

        try:
            self._result = self._api.get_incident_by_id(
                self.incident_id, self.environment
            )
        except HTTPError as e:
            if e.response.status_code == 404:
                raise errors.IncidentNotFoundError(self.incident_id)
            raise
        
        if not self.environment:
            self.environment = self._result['environment']
        
        self.source = self._result.get('source')
        self.sender = self._result.get('sender')
        self.name = self._result.get('incident', {}).get('name')
        self.risk_category = self._result.get('triage_summary', {}).get('risk_category')
        self.risk_level = self._result.get('triage_summary', {}).get('risk_level')
        self.intezer_incident_url = self._result.get('intezer_incident_url')

    def result(self) -> Optional[dict]:
        """
        Get the raw incident result, as received from Intezer Analyze API.

        :raises intezer_sdk.errors.IncidentNotFound: If the incident was not found.
        :return: The raw incident dictionary.
        """
        return self._result

    @classmethod
    def from_id(cls, incident_id: str, environment: Optional[str] = None, api: IntezerApiClient = None) -> 'Incident':
        """
        Create a new Incident instance, and fetch the incident data from the Intezer Analyze API.

        :param incident_id: The incident id.
        :param environment: The environment of the incident.
        :param api: The API connection to Intezer.
        :raises intezer_sdk.errors.IncidentNotFound: If the incident was not found.
        :return: The Incident instance, with the updated incident data.
        """
        new_incident = cls(incident_id, environment=environment, api=api)
        new_incident.fetch_info()
        return new_incident

    def get_raw_data(
        self, environment: Optional[str] = None, raw_data_type: str = 'raw_incident'
    ) -> dict:
        """
        Get raw incident data.

        :param environment: The environment to get raw data from. If not provided, the environment will be taken from the incident.
        :param raw_data_type: The type of raw data to retrieve. Defaults to 'raw_incident'.
        :return: The raw incident data.
        """
        if not self.incident_id and not (self.environment or environment):
            raise ValueError('Incident ID and environment are required to get raw data.')

        return self._api.get_raw_incident_data(
            incident_id=self.incident_id,
            environment=environment or self.environment,
            raw_data_type=raw_data_type,
        )
