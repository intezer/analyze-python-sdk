.. Intezer Python SDK documentation master file

Welcome to Intezer Python SDK's documentation!
==============================================

The ``intezer-sdk`` package wraps the Intezer Analyze 2.0 API
(`full HTTP API documentation <https://docs.intezer.com/reference/>`_).

* GitHub: https://github.com/intezer/analyze-python-sdk
* PyPI: https://pypi.org/project/intezer-sdk

Quick start
-----------

.. code-block:: bash

   pip install intezer-sdk

.. code-block:: python

   from intezer_sdk import api
   from intezer_sdk.analysis import FileAnalysis

   api.set_global_api('<api_key>')

   analysis = FileAnalysis(file_path='/path/to/sample')
   analysis.send(wait=True)
   print(analysis.result())

Guides
------

.. toctree::
   :maxdepth: 2
   :caption: User guide

   getting_started
   alerts
   incidents
   cases
   file_analysis
   url_analysis
   endpoint_analysis
   history
   indexing

API reference
-------------

.. toctree::
   :maxdepth: 2
   :caption: Reference

   modules

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
