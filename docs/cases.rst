Cases
=====

A *case* groups one or more related alerts into a single investigation. The
:mod:`intezer_sdk.cases` module exposes the :class:`~intezer_sdk.cases.Case`
class for fetching case metadata and triage results, and
:func:`~intezer_sdk.cases.query_cases_history` for searching cases.

The Case object
---------------

A :class:`~intezer_sdk.cases.Case` carries the following attributes once
fetched:

* ``case_id`` — the case identifier.
* ``case_title`` — the case title.
* ``case_status`` — one of ``suppressed``, ``new``, ``in_progress``,
  ``on_hold``, ``closed``.
* ``case_priority`` — one of ``informational``, ``low``, ``medium``, ``high``,
  ``escalated``.
* ``alerts_count`` — number of alerts attached to the case.
* ``case_sources`` — product identifiers the case's alerts originated from
  (``s1``, ``cs``, ``microsoft_sentinel``, …).
* ``case_tags`` — tags applied to the case.
* ``risk_category`` — triage-assigned risk category.
* ``case_verdict`` — triage-assigned case verdict.
* ``response_status`` — current response status from triage.
* ``analyst_verdict`` — verdict an analyst set on the case, if any.
* ``intezer_case_url`` — link to the case on Intezer Analyze.

Fetch a case by id
------------------

.. code-block:: python

   from intezer_sdk import api
   from intezer_sdk.cases import Case

   api.set_global_api('<api_key>')

   case = Case.from_id(case_id='<case_id>')
   print(case.case_title, case.case_status, case.case_priority)
   print(case.intezer_case_url)

If the id is unknown, :class:`~intezer_sdk.errors.CaseNotFoundError` is raised.
To construct a :class:`Case` without an immediate API call, use the constructor
and refresh later with :meth:`~intezer_sdk.cases.Case.fetch_info`:

.. code-block:: python

   case = Case(case_id='<case_id>')
   case.fetch_info()

Related entities
----------------

Once a case is loaded you can pull the devices, users, and TTPs Intezer linked
to it:

.. code-block:: python

   for device in case.get_devices():
       print(device)

   for user in case.get_users():
       print(user)

   for ttp in case.get_ttps():
       print(ttp)

Search cases history
--------------------

:func:`~intezer_sdk.cases.query_cases_history` returns a
:class:`~intezer_sdk.cases_results.CasesHistoryResult` that paginates through
all matching cases:

.. code-block:: python

   from intezer_sdk.cases import query_cases_history

   results = query_cases_history(
       sources=['s1', 'microsoft_sentinel'],
       case_statuses=['new', 'in_progress'],
       priorities=['high', 'escalated'],
   )

   for case in results:
       print(case['case_id'], case['case_title'])

   # Or materialize everything at once:
   all_cases = results.all()

See :func:`~intezer_sdk.cases.query_cases_history` for the full filter set
(time range, devices, users, alert identifiers, verdicts, response statuses,
analyst verdicts, assigned account ids, external ticket vendors, …).
