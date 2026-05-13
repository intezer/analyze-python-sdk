Getting started
===============

Installation
------------

.. code-block:: bash

   pip install intezer-sdk

The SDK requires CPython 3.10 or newer.

The global API object
---------------------

Almost every SDK call goes through a single :class:`~intezer_sdk.api.IntezerApiClient`
instance. The convenient way to configure it is to set a *global* instance once
at process start; every SDK class then picks it up automatically when its ``api``
parameter is omitted.

.. code-block:: python

   from intezer_sdk import api
   from intezer_sdk.analysis import FileAnalysis

   api.set_global_api('<api_key>')

   # No `api=` argument needed — the global one is used.
   analysis = FileAnalysis(file_path='/path/to/sample')
   analysis.send(wait=True)

Reading the API key from the environment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you call :func:`~intezer_sdk.api.set_global_api` without a key, the SDK reads
the ``INTEZER_ANALYZE_API_KEY`` environment variable:

.. code-block:: python

   import os
   os.environ['INTEZER_ANALYZE_API_KEY'] = '<api_key>'

   from intezer_sdk import api
   api.set_global_api()  # picks up INTEZER_ANALYZE_API_KEY

Multiple accounts: per-call API instances
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every SDK class accepts an explicit ``api=`` argument that overrides the global
one. This is useful when a single process talks to more than one Intezer account
or environment:

.. code-block:: python

   from intezer_sdk.api import IntezerApiClient
   from intezer_sdk.analysis import FileAnalysis

   tenant_a = IntezerApiClient(api_key='<key_a>')
   tenant_b = IntezerApiClient(api_key='<key_b>')

   analysis_a = FileAnalysis(file_path='sample', api=tenant_a)
   analysis_b = FileAnalysis(file_path='sample', api=tenant_b)

US region
~~~~~~~~~

Customers on the US tenant must point the SDK at the US base URL:

.. code-block:: python

   from intezer_sdk import api

   api.set_global_api(
       api_key='<api_key>',
       base_url='https://us.app.intezer.com/api/',
   )

On-premise
~~~~~~~~~~

Point the global API at your on-premise instance with ``base_url`` and
``on_premise_version``:

.. code-block:: python

   from intezer_sdk import api
   from intezer_sdk.consts import OnPremiseVersion

   api.set_global_api(
       api_key='<api_key>',
       base_url='https://intezer.your-company.com/api',
       on_premise_version=OnPremiseVersion.V22_10,
       verify_ssl=True,
   )

Common options:

* ``base_url`` — root URL of your on-premise API.
* ``on_premise_version`` — declared version of the on-premise deployment;
  the SDK uses this to disable features that are not yet available on your
  version.
* ``verify_ssl`` — set to ``False`` to skip TLS verification.
* ``proxies`` — standard ``requests`` proxies dict.

Custom CA bundle
~~~~~~~~~~~~~~~~

The SDK uses ``requests`` under the hood, so to trust a private CA (typically
when your on-premise instance is fronted by an internal certificate authority)
set the ``REQUESTS_CA_BUNDLE`` environment variable to the CA bundle path before
importing the SDK:

.. code-block:: bash

   export REQUESTS_CA_BUNDLE=/path/to/corporate-ca-bundle.pem

``requests`` picks this up automatically; you don't need to pass anything to
:func:`~intezer_sdk.api.set_global_api`.

Account information and quota
-----------------------------

Once the global API is configured you can introspect the current account or
look up other accounts in the organization:

.. code-block:: python

   from intezer_sdk.account import Account

   me = Account.from_myself()
   print(me.name, me.email)

   quota = Account.get_my_quota()
   print(quota)

   for account in Account.get_organization_account():
       print(account.account_id, account.name)

Error handling
--------------

All SDK exceptions inherit from :class:`intezer_sdk.errors.IntezerError`.
Specific subclasses identify common failures so you can catch them precisely:

.. code-block:: python

   from intezer_sdk import errors
   from intezer_sdk.analysis import FileAnalysis

   try:
       analysis = FileAnalysis(file_hash='<sha256>')
       analysis.send(wait=True)
   except errors.HashDoesNotExistError:
       print('Hash not seen by Intezer yet — submit the file instead.')
   except errors.InsufficientQuotaError:
       print('No quota left for this account.')
   except errors.IntezerError as exc:
       print(f'Other Intezer failure: {exc}')

See the :mod:`intezer_sdk.errors` module reference for the full hierarchy.
