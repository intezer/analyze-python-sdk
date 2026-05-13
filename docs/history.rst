Searching history
=================

The SDK exposes paginated history endpoints for analyses, alerts, devices, and
incidents. Each query helper returns a
:class:`~intezer_sdk.history_results.HistoryResult` subclass — iterate it to walk
the pages, call :meth:`~intezer_sdk.history_results.HistoryResult.all` to
materialize every record, or read
:attr:`~intezer_sdk.history_results.HistoryResult.current_page` for one page at
a time.

Analyses
--------

.. code-block:: python

   import datetime
   from intezer_sdk import api
   from intezer_sdk.analyses_history import (
       query_file_analyses_history,
       query_url_analyses_history,
       query_endpoint_analyses_history,
   )

   api.set_global_api('<api_key>')

   start = datetime.datetime.utcnow() - datetime.timedelta(days=1)
   end = datetime.datetime.utcnow()

   for analysis in query_file_analyses_history(start_date=start, end_date=end):
       print(analysis['analysis_id'], analysis['verdict'])

Each helper accepts filters such as ``sources``, ``verdicts``, ``hashes``, and
``family_names``. See :mod:`intezer_sdk.analyses_history` for the full set.

Alerts, devices, incidents
--------------------------

The same pattern applies to the other history endpoints:

.. code-block:: python

   from intezer_sdk.alerts import query_alerts_history
   from intezer_sdk.devices import query_devices_history
   from intezer_sdk.incidents import query_incidents_history

   for alert in query_alerts_history(start_time=start, end_time=end):
       ...

   for device in query_devices_history(hostnames=['workstation-7']):
       ...

   for incident in query_incidents_history(start_time=start, end_time=end):
       ...

Pagination internals
--------------------

By default the helpers request 100 records per page. The result object handles
pagination automatically while iterating; if you need finer control:

.. code-block:: python

   results = query_file_analyses_history(start_date=start, end_date=end)

   # First page only
   first_page = results.current_page

   # How many total records the server reported
   total = len(results)

   # Materialize all pages
   everything = results.all()
