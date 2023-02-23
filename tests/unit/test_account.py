import uuid
from http import HTTPStatus

import responses

from intezer_sdk import errors
from intezer_sdk.account import Account
from tests.unit.base_test import BaseTest


class AccountSpec(BaseTest):
    def setUp(self):
        super().setUp()

        self.account_id = str(uuid.uuid4())
        self.name = 'name'
        self.account_details = {'account_id': self.account_id,
                                'account_name': self.name,
                                'account_email': 'tig@intezer.com',
                                'created_time': 'Wed, 17 Oct 2018 15:16:45 GMT',
                                'last_sign_in_time': 'Wed, 17 Oct 2018 15:16:45 GMT'}

    def test_get_my_account(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('GET', f'{self.full_url}/accounts/me', json={'result': self.account_details})

            # Act
            account = Account.from_myself()

        # Assert
        self.assertEqual(self.account_id, account.account_id)
        self.assertEqual(self.name, account.name)
        self.assertIsNotNone(account.last_sign_in_time)
        self.assertIsNotNone(account.created_time)

    def test_get_account(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('GET', f'{self.full_url}/accounts/{self.account_id}', json={'result': self.account_details})

            # Act
            account = Account.from_account_id(self.account_id)

        # Assert
        self.assertEqual(self.account_id, account.account_id)
        self.assertEqual(self.name, account.name)
        self.assertIsNotNone(account.last_sign_in_time)
        self.assertIsNotNone(account.created_time)

    def test_compare_account(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('GET', f'{self.full_url}/accounts/{self.account_id}', json={'result': self.account_details})

            # Act
            account1 = Account.from_account_id(self.account_id)
            account2 = Account.from_account_id(self.account_id)

        # Assert
        self.assertEqual(account1, account2)
        account1.account_id = 'asd'
        self.assertNotEqual(account1, account2)
        account1.account_id = None
        self.assertEqual(account1, account1)

    def test_get_account_return_none_when_not_found(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('GET', f'{self.full_url}/accounts/{self.account_id}', status=HTTPStatus.NOT_FOUND)

            # Act
            account = Account.from_account_id(self.account_id)

        # Assert
        self.assertIsNone(account)

    def test_get_organization_accounts(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('GET', f'{self.full_url}/accounts', json={'result': [self.account_details]})

            # Act
            accounts = Account.get_organization_account()

        # Assert
        self.assertEqual(1, len(accounts))
        account = accounts[0]
        self.assertEqual(self.account_id, account.account_id)
        self.assertEqual(self.name, account.name)
        self.assertIsNotNone(account.last_sign_in_time)
        self.assertIsNotNone(account.created_time)

    def test_get_my_quota(self):
        # Arrange
        expected_result = {
            'file_scans': {
                'quota': 100,
                'usage': 100,
                'type': 'monthly'
            },
            'endpoint_scans': {
                'quota': 100,
                'usage': 100,
                'type': 'monthly'
            }
        }
        with responses.RequestsMock() as mock:
            mock.add('GET', f'{self.full_url}/current-quota-usage', json={'result': expected_result})

            # Act
            result = Account.get_my_quota()

            # Assert
            self.assertDictEqual(expected_result, result)

    def test_get_my_quota_raises_when_no_file_quota(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('GET', f'{self.full_url}/current-quota-usage', json={'result': {
                'file_scans': {
                    'quota': 100,
                    'usage': 100
                }
            }})

            # Act and Assert
            with self.assertRaises(errors.InsufficientQuotaError):
                Account.get_my_quota(raise_on_no_file_quota=True)

    def test_get_my_quota_raises_when_no_endpoint_quota(self):
        # Arrange
        with responses.RequestsMock() as mock:
            mock.add('GET', f'{self.full_url}/current-quota-usage', json={'result': {
                'endpoint_scans': {
                    'quota': 100,
                    'usage': 100
                }
            }})

            # Act and Assert
            with self.assertRaises(errors.InsufficientQuotaError):
                Account.get_my_quota(raise_on_no_endpoint_quota=True)
