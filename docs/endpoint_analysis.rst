Endpoint analysis
=================

:class:`~intezer_sdk.endpoint_analysis.EndpointAnalysis` uploads the output of an
endpoint scan to Intezer Analyze for triage. Both online and offline scans are
supported.

Upload an offline scan directory
--------------------------------

When the scanner has produced its output on disk, point an
:class:`EndpointAnalysis` at the directory and submit:

.. code-block:: python

   from pprint import pprint
   from intezer_sdk import api
   from intezer_sdk.endpoint_analysis import EndpointAnalysis

   api.set_global_api('<api_key>')

   analysis = EndpointAnalysis(offline_scan_directory='/path/to/scan_output')
   analysis.send(wait=True)
   pprint(analysis.result())

Look up an existing endpoint analysis
-------------------------------------

If you already have an analysis id (for example from a webhook or from
:attr:`Alert.scans <intezer_sdk.alerts.Alert.scans>`) you can load the
analysis object without re-submitting:

.. code-block:: python

   from intezer_sdk.endpoint_analysis import EndpointAnalysis

   analysis = EndpointAnalysis.from_analysis_id('<analysis_id>')
   pprint(analysis.result())

:meth:`~intezer_sdk.endpoint_analysis.EndpointAnalysis.from_analysis_id` returns
``None`` if no analysis exists for the given id.

Iterate sub-analyses
--------------------

Each interesting artifact found by the endpoint scan becomes a
:class:`~intezer_sdk.sub_analysis.SubAnalysis`:

.. code-block:: python

   for sub_analysis in analysis.get_sub_analyses():
       print(sub_analysis.sha256, sub_analysis.verdict)
