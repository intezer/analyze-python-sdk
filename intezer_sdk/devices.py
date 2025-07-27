import datetime
from typing import Any
from typing import Dict
from typing import List
from typing import Literal
from typing import Optional

from requests import HTTPError

from intezer_sdk import errors
from intezer_sdk._api import IntezerApi
from intezer_sdk._api import IntezerApiClient
from intezer_sdk.api import get_global_api
from intezer_sdk.devices_results import DevicesHistoryResult
from intezer_sdk.util import add_filter

DEFAULT_LIMIT = 100
DEFAULT_OFFSET = 0
INCIDENTS_SEARCH_REQUEST = '/devices/search'


def generate_devices_history_search_filters(*,
                                            device_ids: List[str] = None,
                                            environments: List[str] = None,
                                            offset: int = None,
                                            limit: int = None,
                                            time_range_start: datetime.datetime = None,
                                            time_range_end: datetime.datetime = None,
                                            external_ips: List[str] = None,
                                            host_groups: List[str] = None,
                                            host_tags: List[str] = None,
                                            hostnames: List[str] = None,
                                            managed_by: List[str] = None,
                                            os_names: List[str] = None,
                                            os_versions: List[str] = None,
                                            private_ips: List[str] = None,
                                            cloud_providers: List[str] = None,
                                            host_types: List[str] = None,
                                            last_login_users: List[str] = None,
                                            site_names: List[str] = None,
                                            include_raw_device: bool = None) -> Dict[str, Any]:
    filters = {}
    time_range_start_timestamp = int(time_range_start.timestamp()) if time_range_start else None
    time_range_end_timestamp = int(time_range_end.timestamp()) if time_range_end else None

    add_filter(filters, 'device_ids', device_ids)
    add_filter(filters, 'environments', environments)
    add_filter(filters, 'offset', offset)
    add_filter(filters, 'limit', limit)
    add_filter(filters, 'time_range_start', time_range_start_timestamp)
    add_filter(filters, 'time_range_end', time_range_end_timestamp)
    add_filter(filters, 'external_ips', external_ips)
    add_filter(filters, 'host_groups', host_groups)
    add_filter(filters, 'host_tags', host_tags)
    add_filter(filters, 'hostnames', hostnames)
    add_filter(filters, 'managed_by', managed_by)
    add_filter(filters, 'os_names', os_names)
    add_filter(filters, 'os_versions', os_versions)
    add_filter(filters, 'private_ips', private_ips)
    add_filter(filters, 'cloud_providers', cloud_providers)
    add_filter(filters, 'host_types', host_types)
    add_filter(filters, 'last_login_users', last_login_users)
    add_filter(filters, 'site_names', site_names)
    add_filter(filters, 'include_raw_device', include_raw_device)

    return filters


def query_devices_history(*,
                          api: IntezerApiClient = None,
                          search_mode: Literal['and', 'or'] = 'and',
                          device_ids: List[str] = None,
                          environments: List[str] = None,
                          offset: int = None,
                          limit: int = None,
                          time_range_start: datetime.datetime = None,
                          time_range_end: datetime.datetime = None,
                          external_ips: List[str] = None,
                          host_groups: List[str] = None,
                          host_tags: List[str] = None,
                          hostnames: List[str] = None,
                          managed_by: List[str] = None,
                          os_names: List[str] = None,
                          os_versions: List[str] = None,
                          private_ips: List[str] = None,
                          cloud_providers: List[str] = None,
                          host_types: List[str] = None,
                          last_login_users: List[str] = None,
                          site_names: List[str] = None,
                          include_raw_device: bool = None) -> DevicesHistoryResult:
    """
    Query devices history with query param.

    :param api: Instance of Intezer API for request server.
    :param search_mode: The search mode to use for the query (and / or).
    :param device_ids: Query only this device ids.
    :param environments: Query devices only from these environments.
    :param offset: Offset to start querying from - used for pagination.
    :param limit: Maximum number of devices to return - used for pagination.
    :param time_range_start: Query devices that were discovered after this timestamp (in UTC).
    :param time_range_end: Query devices that were discovered before this timestamp (in UTC).
    :param external_ips: Query devices only with these external ips.
    :param host_groups: Query devices which only appear in these host groups.
    :param host_tags: Query devices only with these host tags.
    :param hostnames: Query devices only with these hostnames.
    :param managed_by: Query devices only managed by these products.
    :param os_names: Query devices only with these OS names.
    :param os_versions: Query devices only with these OS versions.
    :param private_ips: Query devices only with these private ips.
    :param cloud_providers: Query devices from these cloud providers.
    :param host_types: Query devices only with these host types (e.g. server, workstation).
    :param last_login_users: Query devices only with these last login users.
    :param site_names: Query devices only with these site names.
    :param include_raw_device: Include raw device data in the results.

    :return: Device query result from server as Results iterator.
    """
    api = api or get_global_api()
    api.assert_any_on_premise()
    filters = generate_devices_history_search_filters(
        device_ids=device_ids,
        environments=environments,
        offset=offset or DEFAULT_OFFSET,
        limit=limit or DEFAULT_LIMIT,
        time_range_start=time_range_start,
        time_range_end=time_range_end,
        external_ips=external_ips,
        host_groups=host_groups,
        host_tags=host_tags,
        hostnames=hostnames,
        managed_by=managed_by,
        os_names=os_names,
        os_versions=os_versions,
        private_ips=private_ips,
        cloud_providers=cloud_providers,
        host_types=host_types,
        last_login_users=last_login_users,
        site_names=site_names,
        include_raw_device=include_raw_device,
    )

    return DevicesHistoryResult(INCIDENTS_SEARCH_REQUEST, api, filters, search_mode)


class Device:
    """
    The Device class is used to represent a device from the Intezer API.

    :ivar device_id: The device id.
    :vartype device_id: str
    :ivar hostname: The devic hostname.
    :vartype hostname: str
    :ivar host_type: The type of the devic.
    :vartype host_type: str
    :ivar os_type: The os_type of the device.
    :vartype os_type: str
    :ivar os_version: The os version of the devie.
    :vartype os_version: str
    """

    def __init__(self, device_id: Optional[str] = None, api: IntezerApiClient = None):
        """
        Create a new Device instance with the given device_id.
        Please note that this does not query the Intezer Analyze API for the device data, but rather creates a Device
        instance with the given device id.

        If you wish to fetch the device data from the Intezer Analyze API, use the `from_id` class method.

        :param device_id: The device id.
        :param api: The API connection to Intezer.
        """
        self.device_id = device_id

        self._intezer_api_client = api
        self._api = IntezerApi(api or get_global_api())
        self._result: Optional[Dict] = None
        self.hostname: Optional[str] = None
        self.host_type: Optional[str] = None
        self.os_type: Optional[str] = None
        self.os_version: Optional[str] = None

    def fetch_info(self):
        """
        Fetch the device data from the Intezer Analyze API.

        :raises intezer_sdk.errors.DeviceNotFound: If the device was not found.
        """
        if not self.device_id:
            raise ValueError("Device ID is required to fetch device info.")

        try:
            self._result = self._api.get_device_by_id(self.device_id)
        except HTTPError as e:
            if e.response.status_code == 404:
                raise errors.DeviceNotFoundError(self.device_id)
            raise

        self.hostname = self._result.get('hostname')
        self.host_type = self._result.get('host_type')
        self.os_type = self._result.get('os_type')
        self.os_version = self._result.get('os_version')

    def result(self) -> Optional[dict]:
        """
        Get the raw device result, as received from Intezer Analyze API.

        :raises intezer_sdk.errors.IncidentNotFound: If the device was not found.
        :return: The raw device dictionary.
        """
        return self._result

    @classmethod
    def from_id(cls, device_id: str, api: IntezerApiClient = None) -> 'Device':
        """
        Create a new Device instance, and fetch the device data from the Intezer Analyze API.

        :param device_id: The device id.
        :param api: The API connection to Intezer.
        :param timeout: The timeout for the wait operation.
        :raises intezer_sdk.errors.DeviceNotFound: If the device was not found.
        :return: The Device instance, with the updated device data.
        """
        new_device = cls(device_id, api=api)
        new_device.fetch_info()
        return new_device
