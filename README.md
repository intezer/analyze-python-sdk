
# Intezer SDK

Basic SDK for Intezer Analyze API 2.0 

[View full API documentation](https://analyze.intezer.com/api/docs/documentation) (Notice - You must be logged in to Intezer Analyze to access the documentation)

Currently the following options are available in the SDK:

- Analyze by file
- Analyze by SHA256
- Index by file
- Index by SHA256
- Get Latest Analysis
- Account and file related samples
- Code reuse and metadata
- Strings related samples
- Search a family

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
analysis = Analysis(file_path=<file_path>,
                    dynamic_unpacking=<force_dynamic_unpacking>, # optional
                    static_unpacking=<force_static_unpacking>)   # optional
analysis.send(wait=True) 
result = analysis.result()
```
### Analyze By SHA256
```python
analysis = Analysis(file_hash=<file_sha256>)
analysis.send(wait=True)
result = analysis.result()
```

### Analysis result example
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

### Get Latest Analysis
```python
analysis = get_latest_analysis(file_hash: <file_sha256>)
result = analysis.result()
```

### Get Sub Analyses
#### Root Analysis
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
analysis = Analysis(file_hash=<file_sha256>)
analysis.send(wait=True, wait_timeout=datetime.timedelta(minutes=1))
```

## Code examples
You can find more code examples under [analyze-python-sdk/examples/](https://github.com/intezer/analyze-python-sdk/tree/master/examples) directory 

## Changelog

### 1.6.1
- Fix: Handle no iocs correctly 

### 1.6
- Feat: Add analysis summary utility function
- Fix: Handle no ttps correctly 

### 1.5
- Feat: Add family search
- Feat: Support for zip password
- Feat: Add iocs and dynamic ttps to analysis
- Feat: Add capabilities to sub analysis

### 1.4.5
- Feat: Add a timeout option when waiting for operation completion

### 1.4.4
 - Feat: Add Verify SSL toggle to Intezer api to ignore ssl verification

### 1.4.2
 - Fix: Sub analyses should get the API Class like Analysis
 - Doc: Add description to pypi

### Breaking changes in 1.0
 - In `Analysis`: Change `dynamic_unpacking` and `static_unpacking` to `disable_dynamic_unpacking` and `disable_static_unpacking`