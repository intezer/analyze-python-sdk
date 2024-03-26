![PyPI](https://img.shields.io/pypi/v/intezer_sdk)
![Build](https://github.com/intezer/analyze-python-sdk/actions/workflows/test.yml/badge.svg)
# Intezer SDK

The SDK wraps Intezer Analyze API 2.0 ([View full API documentation](https://analyze.intezer.com/api-docs.html))

Currently, the following options are available in the SDK:

- Analyze by file
- Analyze by SHA256
- Analyze Url
- Index by file
- Index by SHA256
- Get Latest Analysis
- Account and file related samples
- Code reuse and Metadata
- IOCs, Dynamic TTPs and Capabilities
- Strings related samples
- Search a family
- Ingest an alert from any source
- Ingest a raw email alert (.msg or .eml file)

## Installation

```bash
pip install intezer-sdk
```

## Using Intezer SDK
### Set global api key
Before using the SDK functionality we should set the api key:
```python
    api.set_global_api('<api_key>')
```

### Analyze By File
```python
analysis = FileAnalysis(file_path=<file_path>,
                    dynamic_unpacking=<force_dynamic_unpacking>, # optional
                    static_unpacking=<force_static_unpacking>)   # optional
analysis.send(wait=True) 
result = analysis.result()
```
### Analyze By SHA256
```python
analysis = FileAnalysis(file_hash=<file_sha256>)
analysis.send(wait=True)
result = analysis.result()
```

### File Analysis result example
```python
{
  'analysis_id': '00000000-0000-0000-0000-000000000000', 
  'analysis_time': 'Sun, 04 Aug 2019 09:38:16 GMT', 
  'analysis_url': 'https://analyze.intezer.com/#/analyses/00000000-0000-0000-0000-000000000000', 
  'family_name': 'Ramnit', 
  'is_private': True, 
  'sha256': '4e553bce90f0b39cd71ba633da5990259e185979c2859ec2e04dd8efcdafe356', 
  'sub_verdict': 'malicious', 
  'verdict': 'malicious'
}
```
### Analyze Url
```python
analysis = UrlAnalysis(url=<url>)
analysis.send(wait=True)
result = analysis.result()
```
### Url Analysis result example
```python
{
    'analysis_id': '70d09f68-c7a3-43a3-a8de-07ec31fbf4ed',
    'domain_info': {
        'creation_date': '1997-08-13 04:00:00.000000',
        'domain_name': 'foo.com',
        'registrar': 'TUCOWS, INC.'
    },
    'indicators': [
    {
        'classification': 'informative',
        'text': 'URL is accessible'
    },
    {
        'classification': 'informative',
        'text': 'Assigned IPv4 domain'
    },
    {
        'classification': 'informative',
        'text': 'Vaild IPv4 domain'
    }
    ],
    'ip': '34.206.39.153',
    'redirect_chain': [
    {
        'response_status': 301,
        'url': 'https://foo.com/'
    },
    {
        'response_status': 200,
        'url': 'http://www.foo.com/'
    }
    ],
    'scanned_url': 'http://www.foo.com/',
    'submitted_url': 'foo.com',
    'downloaded_file': {
        'analysis_id': '8db9a401-a142-41be-9a31-8e5f3642db62',
        'analysis_summary': {
           'verdict_description': 'This file contains code from malicious software, therefore it's very likely that it's malicious.',
           'verdict_name': 'malicious',
           'verdict_title': 'Malicious',
           'verdict_type': 'malicious'
        },
        'sha256': '4293c1d8574dc87c58360d6bac3daa182f64f7785c9d41da5e0741d2b1817fc7'
     },
    'summary': {
        'description': 'No suspicious activity was detected for this URL',
        'title': 'No Threats',
        'verdict_name': 'no_threats',
        'verdict_type': 'no_threats'
    }
}
```
### Index By File
```python
from intezer_sdk import consts

index = Index(file_path=<file_path>, 
              index_as=consts.IndexType.MALICIOUS, 
              family_name=<family_name>)
index.send(wait=True)
index_id = index.index_id
```
### Index By SHA256
```python
from intezer_sdk import consts

index = Index(sha256=<file_sha256>, 
              index_as=consts.IndexType.TRUSTED)
index.send(wait=True)
index_id = index.index_id
```

### Get Latest File Analysis
```python
analysis = FileAnalysis.from_latest_hash_analysis(file_hash: <file_sha256>)
result = analysis.result()
```

### Get Sub Analyses
#### Root File Analysis
```python
root_analysis = analysis.get_root_analysis()
```
#### Sub Analyses
```python
sub_analyses = analysis.get_sub_analyses()
```
#### Code Reuse and Metadata
```python
root_analysis_code_reuse = root_analysis.code_reuse
root_analysis_metadata = root_analysis.metadata

for sub_analysis in sub_analyses:
    sub_analyses_code_reuse = sub_analysis.code_reuse
    sub_analyses_metadata = sub_analysis.metadata
```
#### Related Files by Family
```python
root_analysis_code_reuse = root_analysis.code_reuse

for family in root_analysis_code_reuse['families']:
    operation = root_analysis.find_related_files(family['family_id'], wait=True)
    related_files = operation.get_result()
```
#### Account Related Samples
```python
operation = root_analysis.get_account_related_samples()
related_samples = operation.get_result()
```
#### Vaccine
```python
operation = root_analysis.generate_vaccine()
vaccine = operation.get_result()
```

#### Strings related samples
```python
operation = root_analysis.get_string_related_samples('string_to_relate_to', wait=True)
string_related_samples = operation.get_result()
```

#### Wait with timeout
```python
analysis = FileAnalysis(file_hash=<file_sha256>)
analysis.send(wait=True, wait_timeout=datetime.timedelta(minutes=1))
```

#### Analyses History
 - File

```python
history_results = query_file_analyses_history(
    start_date = <datetime>,
    end_date= <datetime>,
    api = <IntezerApi>
    aggregated_view: <bool>,
    sources=<source>
    verdicts=<verdicts>,
    file_hash=<file_hash>,
    family_names=<family_names>,
    file_name=<file_name>
)
for analyse in history_results:
    print(analyse)
```
 - URL
```python
history_results = query_url_analyses_history(
    start_date = <datetime>,
    end_date=<datetime>,
    aggregated_view=<bool>,
    sources=<sources>,
    verdicts=<verdicts>,
)
for analyse in history_results:
    print(analyse)
```
 - End Point
```python
history_results = query_endpoint_analyses_history(
    start_date = <datetime>,
    end_date=<datetime>,
    aggregated_view=<bool>,
    sources=<sources>,
    verdicts=<verdicts>,
    sub_verdicts=<verdicts>,
    did_download_file=<bool>,
    submitted_url=<submitted_url>
)
for analyse in history_results:
    print(analyse)
```

### Alerts
#### Get alert by id
```python
alert = Alert.from_id(alert_id=alert_id,
                      fetch_scans=False,
                      wait=False)
```

#### Alerts History

```python
history_results = query_file_analyses_history(
    api = <IntezerApi>,
    **filters
)
for analyse in history_results:
    print(analyse)
```

## Code examples
You can find more code examples under [analyze-python-sdk/examples/](https://github.com/intezer/analyze-python-sdk/tree/master/examples) directory 

