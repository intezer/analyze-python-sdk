Analyzing URLs
==============

:class:`~intezer_sdk.analysis.UrlAnalysis` mirrors
:class:`~intezer_sdk.analysis.FileAnalysis` but for URLs. The same submit /
wait / result pattern applies.

Submit and wait
---------------

.. code-block:: python

   from pprint import pprint
   from intezer_sdk import api
   from intezer_sdk.analysis import UrlAnalysis

   api.set_global_api('<api_key>')

   analysis = UrlAnalysis(url='https://example.com/suspicious')
   analysis.send(wait=True)
   pprint(analysis.result())

Look up a previous URL analysis
-------------------------------

When you already have an analysis id, load it directly:

.. code-block:: python

   from intezer_sdk.analysis import UrlAnalysis

   analysis = UrlAnalysis.from_analysis_id('<analysis_id>')
   pprint(analysis.result())

Reuse the latest analysis for a URL
-----------------------------------

To skip re-analysis when a recent result already exists for the same URL, use
:meth:`UrlAnalysis.from_latest_analysis <intezer_sdk.analysis.UrlAnalysis.from_latest_analysis>`.
It returns ``None`` if Intezer has not analyzed the URL before:

.. code-block:: python

   analysis = UrlAnalysis.from_latest_analysis('https://example.com/suspicious')
   if analysis is None:
       print('No prior analysis — submit one explicitly.')
   else:
       pprint(analysis.result())

Downloaded file sub-analysis
----------------------------

If the URL serves a file, the URL analysis links to a file sub-analysis you can
inspect with the standard file APIs:

.. code-block:: python

   analysis = UrlAnalysis(url='https://example.com/payload.exe')
   analysis.send(wait=True)

   downloaded_file_analysis = analysis.downloaded_file_analysis
   if downloaded_file_analysis is not None:
       pprint(downloaded_file_analysis.result())
