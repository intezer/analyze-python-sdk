import datetime
from http import HTTPStatus

import responses

from intezer_sdk import errors
from intezer_sdk.api import get_global_api
from intezer_sdk.devices import Device
from intezer_sdk.devices import generate_devices_history_search_filters
from intezer_sdk.devices import query_devices_history
from intezer_sdk.devices_results import DevicesHistoryResult
from tests.unit.base_test import BaseTest


class DevicesSpec(BaseTest):
    def test_generate_devices_history_search_filters_with_all_parameters(self):
        # Arrange
        device_ids = ['device1', 'device2']
        environments = ['env1', 'env2']
        offset = 10
        limit = 50
        time_range_start = datetime.datetime(2023, 1, 1, 12, 0, 0)
        time_range_end = datetime.datetime(2023, 1, 2, 12, 0, 0)
        external_ips = ['192.168.1.1', '10.0.0.1']
        host_groups = ['group1', 'group2']
        host_tags = ['tag1', 'tag2']
        hostnames = ['hostname1', 'hostname2']
        managed_by = ['manager1', 'manager2']
        os_names = ['Windows', 'Linux']
        os_versions = ['10', '20.04']
        private_ips = ['192.168.1.10', '192.168.1.20']
        cloud_providers = ['AWS', 'Azure']
        host_types = ['server', 'workstation']
        last_login_users = ['user1', 'user2']
        site_names = ['site1', 'site2']

        # Act
        result = generate_devices_history_search_filters(
            device_ids=device_ids,
            environments=environments,
            offset=offset,
            limit=limit,
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
            site_names=site_names
        )

        # Assert
        self.assertEqual(result['device_ids'], device_ids)
        self.assertEqual(result['environments'], environments)
        self.assertEqual(result['offset'], offset)
        self.assertEqual(result['limit'], limit)
        self.assertEqual(result['time_range_start'], time_range_start.timestamp())
        self.assertEqual(result['time_range_end'], time_range_end.timestamp())
        self.assertEqual(result['external_ips'], external_ips)
        self.assertEqual(result['host_groups'], host_groups)
        self.assertEqual(result['host_tags'], host_tags)
        self.assertEqual(result['hostnames'], hostnames)
        self.assertEqual(result['managed_by'], managed_by)
        self.assertEqual(result['os_names'], os_names)
        self.assertEqual(result['os_versions'], os_versions)
        self.assertEqual(result['private_ips'], private_ips)
        self.assertEqual(result['cloud_providers'], cloud_providers)
        self.assertEqual(result['host_types'], host_types)
        self.assertEqual(result['last_login_users'], last_login_users)
        self.assertEqual(result['site_names'], site_names)

    def test_generate_devices_history_search_filters_with_none_parameters(self):
        # Arrange & Act
        result = generate_devices_history_search_filters()

        # Assert
        self.assertEqual(result, {})

    def test_generate_devices_history_search_filters_with_datetime_none(self):
        # Arrange & Act
        result = generate_devices_history_search_filters(
            time_range_start=None,
            time_range_end=None
        )

        # Assert
        self.assertEqual(result, {})

    def test_query_devices_history_returns_devices_history_result(self):
        # Arrange
        device_ids = ['device1']

        # Act
        result = query_devices_history(device_ids=device_ids)

        # Assert
        self.assertIsInstance(result, DevicesHistoryResult)

    def test_query_devices_history_with_search_mode(self):
        # Arrange
        device_ids = ['device1']

        # Act
        result = query_devices_history(device_ids=device_ids, search_mode='or')

        # Assert
        self.assertIsInstance(result, DevicesHistoryResult)
        self.assertEqual(result._search_mode, 'or')

    def test_device_init(self):
        # Arrange
        device_id = 'test_device_id'

        # Act
        device = Device(device_id)

        # Assert
        self.assertEqual(device.device_id, device_id)
        self.assertIsNone(device.hostname)
        self.assertIsNone(device.host_type)
        self.assertIsNone(device.os_type)
        self.assertIsNone(device.os_version)

    def test_device_fetch_info_success(self):
        # Arrange
        device_id = 'test_device_id'
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/devices/get-by-id',
                     status=HTTPStatus.OK,
                     json={
                         'result': {
                             'hostname': 'test_hostname',
                             'host_type': 'server',
                             'os_type': 'Windows',
                             'os_version': '10'
                         }
                     })

            device = Device(device_id)

            # Act
            device.fetch_info()

            # Assert
            self.assertEqual(device.hostname, 'test_hostname')
            self.assertEqual(device.host_type, 'server')
            self.assertEqual(device.os_type, 'Windows')
            self.assertEqual(device.os_version, '10')

    def test_device_fetch_info_without_device_id_raises_error(self):
        # Arrange
        device = Device()

        # Act & Assert
        with self.assertRaises(ValueError) as context:
            device.fetch_info()

        self.assertEqual(str(context.exception), "Device ID is required to fetch device info.")

    def test_device_fetch_info_not_found_raises_error(self):
        # Arrange
        device_id = 'test_device_id'
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/devices/get-by-id',
                     status=HTTPStatus.NOT_FOUND,
                     json={'error': 'Device not found'})

            device = Device(device_id)

            # Act & Assert
            with self.assertRaises(errors.DeviceNotFoundError):
                device.fetch_info()

    def test_device_result_returns_raw_data(self):
        # Arrange
        device_id = 'test_device_id'
        expected_result = {
            'hostname': 'test_hostname',
            'host_type': 'server',
            'os_type': 'Windows'
        }

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/devices/get-by-id',
                     status=HTTPStatus.OK,
                     json={'result': expected_result})

            device = Device(device_id)
            device.fetch_info()

            # Act
            result = device.result()

            # Assert
            self.assertEqual(result, expected_result)

    def test_device_result_returns_none_when_no_data_fetched(self):
        # Arrange
        device = Device('test_device_id')

        # Act
        result = device.result()

        # Assert
        self.assertIsNone(result)

    def test_device_from_id_success(self):
        # Arrange
        device_id = 'test_device_id'
        with responses.RequestsMock() as mock:
            mock.add('GET',
                     url=f'{self.full_url}/devices/get-by-id',
                     status=HTTPStatus.OK,
                     json={
                         'result': {
                             'hostname': 'test_hostname',
                             'host_type': 'server',
                             'os_type': 'Windows',
                             'os_version': '10'
                         }
                     })

            # Act
            device = Device.from_id(device_id)

            # Assert
            self.assertEqual(device.device_id, device_id)
            self.assertEqual(device.hostname, 'test_hostname')
            self.assertEqual(device.host_type, 'server')
            self.assertEqual(device.os_type, 'Windows')
            self.assertEqual(device.os_version, '10')


class DevicesHistoryResultSpec(BaseTest):
    def test_devices_history_result_init(self):
        # Arrange
        request_url_path = '/devices/search'
        filters = {'device_ids': ['device1']}
        search_mode = 'and'
        api = get_global_api()

        # Act
        result = DevicesHistoryResult(request_url_path, api, filters, search_mode)

        # Assert
        self.assertEqual(result._request_url_path, request_url_path)
        self.assertEqual(result._api, api)
        self.assertEqual(result.filters, filters)
        self.assertEqual(result._search_mode, search_mode)

    def test_devices_history_result_init_with_default_search_mode(self):
        # Arrange
        request_url_path = '/devices/search'
        filters = {'device_ids': ['device1']}
        api = get_global_api()

        # Act
        result = DevicesHistoryResult(request_url_path, api, filters)

        # Assert
        self.assertEqual(result._search_mode, 'and')

    def test_devices_history_result_fetch_history_success(self):
        # Arrange
        request_url_path = '/devices/search'
        filters = {'device_ids': ['device1']}
        devices_data = [
            {
                'device_id': 'device1',
                'hostname': 'test_hostname',
                'host_type': 'server',
                'os_type': 'Windows'
            }
        ]

        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/devices/search',
                     status=HTTPStatus.OK,
                     json={
                         'devices_count': 1,
                         'devices': devices_data
                     })

            result = DevicesHistoryResult(request_url_path, get_global_api(), filters)

            # Act
            count, devices = result._fetch_history(request_url_path, filters)

            # Assert
            self.assertEqual(count, 1)
            self.assertEqual(devices, devices_data)

    def test_devices_history_result_fetch_history_empty_result(self):
        # Arrange
        request_url_path = '/devices/search'
        filters = {'device_ids': ['nonexistent_device']}

        with responses.RequestsMock() as mock:
            mock.add('POST',
                     url=f'{self.full_url}/devices/search',
                     status=HTTPStatus.OK,
                     json={
                         'devices_count': 0,
                         'devices': []
                     })

            result = DevicesHistoryResult(request_url_path, get_global_api(), filters)

            # Act
            count, devices = result._fetch_history(request_url_path, filters)

            # Assert
            self.assertEqual(count, 0)
            self.assertEqual(devices, [])

    def test_devices_history_result_fetch_history_includes_search_mode(self):
        # Arrange
        request_url_path = '/devices/search'
        filters = {'device_ids': ['device1']}
        search_mode = 'or'

        with responses.RequestsMock() as mock:
            def request_callback(request):
                # Verify that search_mode is included in the request data
                import json
                data = json.loads(request.body)
                assert data['search_mode'] == search_mode
                return (HTTPStatus.OK, {}, json.dumps({
                    'devices_count': 1,
                    'devices': [{'device_id': 'device1'}]
                }))

            mock.add_callback('POST',
                              url=f'{self.full_url}/devices/search',
                              callback=request_callback)

            result = DevicesHistoryResult(request_url_path, get_global_api(), filters, search_mode)

            # Act
            count, devices = result._fetch_history(request_url_path, filters)

            # Assert
            self.assertEqual(count, 1)
            self.assertEqual(devices, [{'device_id': 'device1'}])
