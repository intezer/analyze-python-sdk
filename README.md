
# Intezer SDK

Basic SDK for Intezer Analyze API 2.0 

[View full API documentation](https://analyze.intezer.com/api/docs/documentation) (Notice - You must be logged in to Intezer Analyze to access the documentation)

Currently the following options are available in the SDK:

- Analyze by file
- Analyze by SHA256
- Index by file
- Index by SHA256
- Get Latest Analysis

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

## Code examples
You can find more code examples under [analyze-python-sdk/examples/](https://github.com/intezer/analyze-python-sdk/tree/master/examples) directory 
