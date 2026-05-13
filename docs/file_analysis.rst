Analyzing files
===============

:class:`~intezer_sdk.analysis.FileAnalysis` is the entry point for sending a file
or hash to Intezer Analyze, polling for results, and inspecting sub-analyses.

Submit a file and wait for the verdict
--------------------------------------

.. code-block:: python

   from pprint import pprint
   from intezer_sdk import api
   from intezer_sdk.analysis import FileAnalysis

   api.set_global_api('<api_key>')

   analysis = FileAnalysis(file_path='/path/to/sample.exe')
   analysis.send(wait=True)
   pprint(analysis.result())

Submit asynchronously
---------------------

When ``wait=False`` (the default), :meth:`~intezer_sdk.base_analysis.Analysis.send`
returns immediately. Poll with :meth:`~intezer_sdk.base_analysis.Analysis.wait_for_completion`
or :meth:`~intezer_sdk.base_analysis.Analysis.check_status`.

.. code-block:: python

   import datetime

   analysis = FileAnalysis(file_path='/path/to/sample.exe')
   analysis.send()

   # Block with a timeout, raising TimeoutError if the analysis is not finished.
   analysis.wait_for_completion(timeout=datetime.timedelta(minutes=5))
   pprint(analysis.result())

The wait pattern
----------------

There are three equivalent ways to wait for an analysis to finish; pick whichever
fits the surrounding flow:

.. code-block:: python

   import datetime

   # 1. Send and block until done.
   analysis = FileAnalysis(file_path='/path/to/sample.exe')
   analysis.send(wait=True)

   # 2. Send and block until done, with a timeout.
   analysis = FileAnalysis(file_path='/path/to/sample.exe')
   analysis.send(wait=True, wait_timeout=datetime.timedelta(minutes=2))

   # 3. Send asynchronously, do other work, then wait separately.
   analysis = FileAnalysis(file_path='/path/to/sample.exe')
   analysis.send()
   ...  # do other work
   analysis.wait_for_completion(timeout=datetime.timedelta(minutes=2))

All three raise :class:`TimeoutError` when the timeout elapses. The same pattern
applies to :class:`~intezer_sdk.analysis.UrlAnalysis` and
:class:`~intezer_sdk.endpoint_analysis.EndpointAnalysis`.

Submit by hash
--------------

If the file has already been seen by Intezer you can analyze it by sha256
without uploading the bytes. If the hash is unknown,
:class:`~intezer_sdk.errors.HashDoesNotExistError` is raised.

.. code-block:: python

   from intezer_sdk import errors

   try:
       analysis = FileAnalysis(file_hash='<sha256>')
       analysis.send(wait=True)
   except errors.HashDoesNotExistError:
       # Fall back to uploading the bytes.
       analysis = FileAnalysis(file_path='/path/to/sample')
       analysis.send(wait=True)

Reuse the latest analysis
-------------------------

Skip re-analysis when a recent result already exists:

.. code-block:: python

   analysis = FileAnalysis.from_latest_hash_analysis(file_hash='<sha256>')
   if analysis is None:
       print('No prior analysis — submit one explicitly.')
   else:
       pprint(analysis.result())

Inspect sub-analyses
--------------------

Composed files (archives, installers, packed binaries, …) yield a tree of
:class:`~intezer_sdk.sub_analysis.SubAnalysis` objects after the parent
finishes:

.. code-block:: python

   analysis = FileAnalysis(file_path='/path/to/installer.msi')
   analysis.send(wait=True)

   for sub_analysis in analysis.get_sub_analyses():
       print(sub_analysis.sha256, sub_analysis.source)
       print(sub_analysis.code_reuse)
       print(sub_analysis.metadata)

Use :meth:`~intezer_sdk.analysis.FileAnalysis.get_root_analysis` to access the
root sub-analysis directly.

Submission options
------------------

Common keyword arguments for :class:`~intezer_sdk.analysis.FileAnalysis`:

* ``disable_dynamic_unpacking`` — skip dynamic unpacking.
* ``disable_static_unpacking`` — skip static unpacking.
* ``code_item_type`` — one of :class:`~intezer_sdk.consts.CodeItemType` (e.g. ``file``, ``memory_module``).
* ``zip_password`` — password used to extract a zipped sample.
* ``sandbox_command_line_arguments`` — arguments passed to the sample inside the sandbox.
* ``file_name`` — display name to use in Intezer Analyze.

See :class:`intezer_sdk.analysis.FileAnalysis` for the full signature.
