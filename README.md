[![PyPI](https://img.shields.io/pypi/v/intezer_sdk)](https://pypi.org/project/intezer-sdk/)
[![Build](https://github.com/intezer/analyze-python-sdk/actions/workflows/test.yml/badge.svg)](https://github.com/intezer/analyze-python-sdk/actions/workflows/test.yml)
[![Documentation Status](https://readthedocs.org/projects/analyze-python-sdk/badge/?version=latest)](https://intezer-python-sdk.readthedocs.io/en/latest/)

# Intezer SDK

The SDK wraps the Intezer Platform API 2.0 ([full HTTP API documentation](https://docs.intezer.com/reference/)).

📖 **Full documentation**: https://intezer-python-sdk.readthedocs.io/

What you can do with the SDK:

- Analyze files, URLs and endpoint scans
- Send and retrieve alerts (raw and phishing emails)
- Inspect incidents and cases (devices, users, TTPs)
- Search analyses, alerts, incidents, cases and devices history
- Index files as trusted or malicious and look up genetic families
- Get code reuse, metadata, IOCs, dynamic TTPs, capabilities and related samples

## Installation

```bash
pip install intezer-sdk
```

The SDK requires CPython 3.10 or newer.

## Quick start

Configure the global API once, then use any SDK class:

```python
from intezer_sdk import api
from intezer_sdk.analysis import FileAnalysis

api.set_global_api('<api_key>')

analysis = FileAnalysis(file_path='/path/to/sample')
analysis.send(wait=True)
print(analysis.result())
```

The API key can also be read from the `INTEZER_ANALYZE_API_KEY` environment
variable. See the [Getting started guide](https://intezer-python-sdk.readthedocs.io/en/latest/getting_started.html)
for US region, on-premise, and multi-tenant setups.

## A taste of the SDK

```python
# Analyze a URL
from intezer_sdk.analysis import UrlAnalysis
analysis = UrlAnalysis(url='https://example.com/suspicious')
analysis.send(wait=True)

# Fetch an alert and its scans
from intezer_sdk.alerts import Alert
alert = Alert.from_id(alert_id='<alert_id>', wait=True, fetch_scans=True)
print(alert.verdict, alert.family_name)

# Look up a case
from intezer_sdk.cases import Case
case = Case.from_id(case_id='<case_id>')
print(case.case_title, case.case_status, case.case_priority)
```

For the full set of examples — wait patterns, sub-analyses, alert ingestion,
incident and case search, indexing, history queries, on-premise setup — see the
[hosted documentation](https://intezer-python-sdk.readthedocs.io/).
