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
                     '{}/families/{}/info'.format(self.full_url, family_id),
                     json={'result': {'family_id': family_id,
                                      'family_name': expected_name,
                                      'family_type': 'malware'}})
            # Act
            name = family.name

        self.assertEqual(name, expected_name)

    def test_access_to_family_name_fetches_the_data_from_cloud_only_once(self):
        # Arrange
        family_id = str(uuid.uuid4())
        expected_name = 'Burla'
        family = Family(family_id)

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     '{}/families/{}/info'.format(self.full_url, family_id),
                     json={'result': {'family_id': family_id,
                                      'family_name': expected_name,
                                      'family_type': 'malware'}})
            # Act
            _ = family.name
            name = family.name

        self.assertEqual(name, expected_name)

    def test_access_to_family_type_fetches_the_data_from_cloud(self):
        # Arrange
        family_id = str(uuid.uuid4())
        expected_type = 'malware'
        family = Family(family_id)

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     '{}/families/{}/info'.format(self.full_url, family_id),
                     json={'result': {'family_id': family_id,
                                      'family_name': 'Burla',
                                      'family_type': expected_type}})
            # Act
            family_type = family.type

        self.assertEqual(family_type, expected_type)

    def test_access_to_family_type_fetches_the_data_from_cloud_only_once(self):
        # Arrange
        family_id = str(uuid.uuid4())
        expected_type = 'malware'
        family = Family(family_id)

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     '{}/families/{}/info'.format(self.full_url, family_id),
                     json={'result': {'family_id': family_id,
                                      'family_name': 'Burla',
                                      'family_type': expected_type}})
            # Act
            _ = family.type
            family_type = family.type

        self.assertEqual(family_type, expected_type)

    def test_fetch_family_raise_when_family_not_found(self):
        # Arrange
        family_id = str(uuid.uuid4())
        family = Family(family_id)

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     '{}/families/{}/info'.format(self.full_url, family_id),
                     status=HTTPStatus.NOT_FOUND)
            # Act and assert
            with self.assertRaises(errors.FamilyNotFoundError):
                family.fetch_info()

    def test_get_family_by_name_return_family(self):
        # Arrange
        family_id = str(uuid.uuid4())
        family_name = 'Burla'

        with responses.RequestsMock() as mock:
            mock.add('GET',
                     '{}/families'.format(self.full_url),
                     json={'result': {'family_id': family_id, 'family_name': family_name}})

            # Act
            family = get_family_by_name(family_name)

        # Assert
        self.assertEqual(family.family_id, family_id)
        self.assertEqual(family.name, family_name)

    def test_get_family_by_name_return_none_when_family_not_found(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('GET', '{}/families'.format(self.full_url), status=HTTPStatus.NOT_FOUND)

            # Act
            family = get_family_by_name('Burla')

        # Assert
        self.assertIsNone(family)
