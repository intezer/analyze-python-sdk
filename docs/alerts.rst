Alerts
======

The :mod:`intezer_sdk.alerts` module is the entry point for sending alerts to
Intezer for triage and for retrieving the resulting verdicts. The
:class:`~intezer_sdk.alerts.Alert` class wraps a single alert: it tracks the
triage status, exposes the verdict and family identification once finished, and
gives access to the underlying scans (file / URL / endpoint analyses) that
Intezer ran on the alert's artifacts.

The Alert object
----------------

An :class:`~intezer_sdk.alerts.Alert` is created either by submitting a new
alert (e.g. :meth:`Alert.send_phishing_email <intezer_sdk.alerts.Alert.send_phishing_email>`)
or by fetching an existing one (:meth:`Alert.from_id <intezer_sdk.alerts.Alert.from_id>`).
Once it has finished processing, the instance carries the following attributes:

* ``alert_id`` — the alert identifier.
* ``status`` — an :class:`~intezer_sdk.consts.AlertStatusCode` (``IN_PROGRESS``,
  ``FINISHED``, or ``NOT_FOUND``).
* ``verdict`` — Intezer's triage verdict, drawn from
  :class:`~intezer_sdk.consts.AlertVerdict` (e.g. ``confirmed_threat``,
  ``likely_true_positive``, ``suspicious_behavior``, ``false_positive``,
  ``inconclusive``).
* ``family_name`` — name of the genetic family Intezer identified, if any.
* ``source`` — the source product the alert was ingested from, e.g. ``s1``
  (SentinelOne), ``cs`` (CrowdStrike), ``splunk_siem``, ``microsoft_sentinel``,
  ``xsoar``.
* ``sender`` — alert sender, when one was provided.
* ``intezer_alert_url`` — link to the alert on Intezer Analyze.
* ``environment`` — the environment the alert belongs to.
* ``scans`` — populated by :meth:`~intezer_sdk.alerts.Alert.fetch_scans` with
  the file / URL / endpoint analyses Intezer ran on the alert.

Send a phishing email
---------------------

For phishing reports, pass the raw EML and let Intezer extract attachments and
URLs automatically:

.. code-block:: python

   import io
   from intezer_sdk import api
   from intezer_sdk.alerts import Alert

   api.set_global_api('<api_key>')

   with open('/path/to/reported.eml', 'rb') as f:
       raw_email = io.BytesIO(f.read())

   alert = Alert.send_phishing_email(raw_email=raw_email, wait=True)
   print(alert.alert_id, alert.verdict, alert.family_name)

You can also pass ``email_path`` instead of a stream, and override the default
verdict, sender, or zip password used to extract password-protected EMLs. See
:meth:`~intezer_sdk.alerts.Alert.send_phishing_email` for the full signature.

Fetch an alert by id
--------------------

.. code-block:: python

   from intezer_sdk.alerts import Alert

   alert = Alert.from_id(
       alert_id='<alert_id>',
       wait=True,            # block until triage finishes
       fetch_scans=True,     # also load the underlying scans
   )

   print(alert.status, alert.verdict)
   for scan in alert.scans:
       print(scan)

If the alert is still being triaged when you call ``from_id`` with
``wait=False``, :class:`~intezer_sdk.errors.AlertInProgressError` is raised; if
the id is unknown, :class:`~intezer_sdk.errors.AlertNotFoundError`.

Polling and waiting
-------------------

When you submitted or fetched the alert without waiting, drive the state machine
yourself:

.. code-block:: python

   import datetime

   alert = Alert.from_id(alert_id='<alert_id>', wait=False)

   alert.check_status()  # refresh `status`, `verdict`, `family_name`, …
   if alert.is_running():
       alert.wait_for_completion(timeout=datetime.timedelta(minutes=5))

   result = alert.result()  # raw triage payload as a dict

:meth:`~intezer_sdk.alerts.Alert.result` raises
:class:`~intezer_sdk.errors.AlertInProgressError` if the alert hasn't finished
yet and :class:`~intezer_sdk.errors.AlertNotFoundError` if the id is unknown.

Underlying scans
----------------

Intezer runs file, URL, and endpoint analyses on the artifacts inside the
alert. Load them with :meth:`~intezer_sdk.alerts.Alert.fetch_scans`:

.. code-block:: python

   from intezer_sdk.analysis import FileAnalysis, UrlAnalysis
   from intezer_sdk.endpoint_analysis import EndpointAnalysis

   alert.fetch_scans()
   for scan in alert.scans:
       if isinstance(scan, FileAnalysis):
           print('file', scan.result())
       elif isinstance(scan, UrlAnalysis):
           print('url', scan.result())
       elif isinstance(scan, EndpointAnalysis):
           print('endpoint', scan.result())

You can also pull the original raw alert payload that was ingested:

.. code-block:: python

   raw_alert = alert.get_raw_data()  # raw_data_type defaults to 'raw_alert'

Notify and delete
-----------------

.. code-block:: python

   notified_channels = alert.notify()
   print('Notified:', notified_channels)

   operation = alert.delete(wait_for_completion=True)

Bulk fetch by id
----------------

To fetch many alerts in a single request, use
:func:`~intezer_sdk.alerts.get_alerts_by_alert_ids`:

.. code-block:: python

   from intezer_sdk.alerts import get_alerts_by_alert_ids

   count, alerts = get_alerts_by_alert_ids(['id-1', 'id-2', 'id-3'])
   for alert in alerts:
       print(alert['alert_id'], alert.get('triage_result'))

Search alert history
--------------------

:func:`~intezer_sdk.alerts.query_alerts_history` returns an
:class:`~intezer_sdk.alerts_results.AlertsHistoryResult` that paginates through
all alerts matching the filter:

.. code-block:: python

   import datetime
   from intezer_sdk.alerts import query_alerts_history

   results = query_alerts_history(
       start_time=datetime.datetime.utcnow() - datetime.timedelta(days=7),
       end_time=datetime.datetime.utcnow(),
       sources=['s1', 'cs'],
       alert_verdicts=['confirmed_threat', 'likely_true_positive'],
   )

   for alert in results:
       print(alert['alert_id'], alert['verdict'])

   # Or materialize everything at once:
   all_alerts = results.all()

The ``sources`` filter accepts product identifiers (``s1``, ``cs``,
``microsoft_sentinel``, ``splunk_siem``, ``xsoar``, …) and ``alert_verdicts``
accepts :class:`~intezer_sdk.consts.AlertVerdict` values
(``confirmed_threat``, ``false_positive``, ``inconclusive``, …).

The query helper accepts a wide range of filters (hostnames, file hashes,
device ids, email metadata, time-filter mode, …); see
:func:`~intezer_sdk.alerts.query_alerts_history` for the full list.
