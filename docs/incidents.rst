Incidents
=========

The :mod:`intezer_sdk.incidents` module wraps Intezer incidents. The
:class:`~intezer_sdk.incidents.Incident` class exposes the incident's metadata
and triage summary; the :func:`~intezer_sdk.incidents.query_incidents_history`
helper paginates through incidents matching a filter.

The Incident object
-------------------

An :class:`~intezer_sdk.incidents.Incident` carries the following attributes
once fetched:

* ``incident_id`` — the incident identifier.
* ``name`` — the incident name.
* ``source`` — the product the incident was ingested from (same identifiers as
  for alerts: ``s1``, ``cs``, ``microsoft_sentinel``, …).
* ``sender`` — the incident sender, when one was provided.
* ``risk_category`` — Intezer's risk category for the incident.
* ``risk_level`` — one of ``informational``, ``low``, ``medium``, ``high``,
  ``critical``.
* ``intezer_incident_url`` — link to the incident on Intezer Analyze.
* ``environment`` — the environment the incident belongs to.

Fetch an incident by id
-----------------------

.. code-block:: python

   from intezer_sdk import api
   from intezer_sdk.incidents import Incident

   api.set_global_api('<api_key>')

   incident = Incident.from_id(incident_id='<incident_id>')
   print(incident.name, incident.risk_level, incident.intezer_incident_url)

If the id is unknown, :class:`~intezer_sdk.errors.IncidentNotFoundError` is
raised. To construct an :class:`Incident` without an immediate API call, use the
constructor and refresh later with
:meth:`~intezer_sdk.incidents.Incident.fetch_info`:

.. code-block:: python

   incident = Incident(incident_id='<incident_id>', environment='production')
   incident.fetch_info()

Raw incident data
-----------------

Pull the original payload Intezer ingested for the incident:

.. code-block:: python

   raw_incident = incident.get_raw_data()
   # Or override the environment / raw data type:
   raw_incident = incident.get_raw_data(environment='production', raw_data_type='raw_incident')

Search incidents history
------------------------

:func:`~intezer_sdk.incidents.query_incidents_history` returns an
:class:`~intezer_sdk.incidents_results.IncidentsHistoryResult` that paginates
through all matching incidents:

.. code-block:: python

   import datetime
   from intezer_sdk.incidents import query_incidents_history

   results = query_incidents_history(
       start_time=datetime.datetime.utcnow() - datetime.timedelta(days=7),
       end_time=datetime.datetime.utcnow(),
       sources=['s1', 'microsoft_sentinel'],
       severities=['high', 'critical'],
   )

   for incident in results:
       print(incident['incident_id'], incident['name'])

   # Or materialize everything at once:
   all_incidents = results.all()

See :func:`~intezer_sdk.incidents.query_incidents_history` for the full list of
filters (statuses, related alert ids, risk categories, time-filter mode, …).
