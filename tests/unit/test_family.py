import uuid
from http import HTTPStatus

import responses

from intezer_sdk import errors
from intezer_sdk.family import Family
from intezer_sdk.family import get_family_by_name
from tests.unit.base_test import BaseTest


class FamilySpec(BaseTest):

    def test_access_to_family_name_fetches_the_data_from_cloud(self):
        # Arrange
        family_id = str(uuid.uuid4())
        expected_name = 'Burla'
        family = Family(family_id)

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     f'{self.full_url}/families/{family_id}/info',
                     json={'result': {'family_id': family_id,
                                      'family_name': expected_name,
                                      'family_type': 'malware'}})
            # Act
            name = family.name

        # Assert
        self.assertEqual(expected_name, name)
    def test_from_family_id_returns_family(self):
        # Arrange
        family_id = str(uuid.uuid4())
        family_name = 'Burla'

        with responses.RequestsMock() as mock:
            family_type = 'malware'
            mock.add('GET',
                     f'{self.full_url}/families/{family_id}/info',
                     json={'result': {'family_id': family_id,
                                      'family_name': family_name,
                                      'family_type': family_type}})
            # Act
            family = Family.from_family_id(family_id)

        # Assert
        self.assertIsNotNone(family)
        self.assertEqual(family_id, family.family_id)
        self.assertEqual(family_name, family.name)
        self.assertEqual(family_type, family.type)

    def test_access_to_family_name_fetches_the_data_from_cloud_only_once(self):
        # Arrange
        family_id = str(uuid.uuid4())
        expected_name = 'Burla'
        family = Family(family_id)

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     f'{self.full_url}/families/{family_id}/info',
                     json={'result': {'family_id': family_id,
                                      'family_name': expected_name,
                                      'family_type': 'malware'}})
            # Act
            _ = family.name
            name = family.name

        # Assert
        self.assertEqual(expected_name, name)

    def test_access_to_family_type_fetches_the_data_from_cloud(self):
        # Arrange
        family_id = str(uuid.uuid4())
        expected_type = 'malware'
        family = Family(family_id)

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     f'{self.full_url}/families/{family_id}/info',
                     json={'result': {'family_id': family_id,
                                      'family_name': 'Burla',
                                      'family_type': expected_type}})
            # Act
            family_type = family.type

        # Assert
        self.assertEqual(expected_type, family_type)

    def test_access_to_family_type_fetches_the_data_from_cloud_only_once(self):
        # Arrange
        family_id = str(uuid.uuid4())
        expected_type = 'malware'
        family = Family(family_id)

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     f'{self.full_url}/families/{family_id}/info',
                     json={'result': {'family_id': family_id,
                                      'family_name': 'Burla',
                                      'family_type': expected_type}})
            # Act
            _ = family.type
            family_type = family.type

        # Assert
        self.assertEqual(expected_type, family_type)

    def test_fetch_family_raise_when_family_not_found(self):
        # Arrange
        family_id = str(uuid.uuid4())
        family = Family(family_id)

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     f'{self.full_url}/families/{family_id}/info',
                     status=HTTPStatus.NOT_FOUND)

            # Act and Assert
            with self.assertRaises(errors.FamilyNotFoundError):
                family.fetch_info()
    def test_from_family_id_return_none_when_family_not_found(self):
        # Arrange
        family_id = str(uuid.uuid4())

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     f'{self.full_url}/families/{family_id}/info',
                     status=HTTPStatus.NOT_FOUND)
            # Act
            family = Family.from_family_id(family_id)

        # Assert
        self.assertIsNone(family)

    def test_get_family_by_name_return_family(self):
        # Arrange
        family_id = str(uuid.uuid4())
        family_name = 'Burla'

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     f'{self.full_url}/families',
                     json={'result': {'family_id': family_id, 'family_name': family_name}})

            # Act
            family = get_family_by_name(family_name)

        # Assert
        self.assertEqual(family_id, family.family_id)
        self.assertEqual(family_name, family.name)

    def test_get_family_by_name_return_none_when_family_not_found(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('GET', f'{self.full_url}/families', status=HTTPStatus.NOT_FOUND)

            # Act
            family = get_family_by_name('Burla')

        # Assert
        self.assertIsNone(family)
