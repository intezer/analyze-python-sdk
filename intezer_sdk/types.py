from typing import Dict
from typing import TypedDict
from typing import NotRequired
from typing import List
from typing import Any


class FieldDefinitionSchema(TypedDict):
    from_path: NotRequired[str]
    value: NotRequired[Any]
    value_map: NotRequired[Dict]
    is_multi: NotRequired[bool]


class DeviceDefinitionSchema(TypedDict):
    hostname: FieldDefinitionSchema
    device_id: NotRequired[FieldDefinitionSchema]
    os_type: NotRequired[FieldDefinitionSchema]
    os_name: NotRequired[FieldDefinitionSchema]


class EvidenceDefinitionSchema(TypedDict):
    evidence_type: FieldDefinitionSchema
    evidence_value: NotRequired[FieldDefinitionSchema]
    creation_time: NotRequired[FieldDefinitionSchema]
    file_type: NotRequired[FieldDefinitionSchema]
    file_path: NotRequired[FieldDefinitionSchema]
    command_line: NotRequired[FieldDefinitionSchema]
    file_name: NotRequired[FieldDefinitionSchema]
    list_path: str


class AlertDefinitionMapping(TypedDict):
    alert_id: FieldDefinitionSchema
    alert_type: NotRequired[FieldDefinitionSchema]
    alert_sub_type: NotRequired[FieldDefinitionSchema]
    creation_time: FieldDefinitionSchema
    alert_url: NotRequired[FieldDefinitionSchema]
    alert_title: NotRequired[FieldDefinitionSchema]
    severity: NotRequired[FieldDefinitionSchema]
    is_mitigated: NotRequired[FieldDefinitionSchema]
    classification: NotRequired[FieldDefinitionSchema]
    device: NotRequired[DeviceDefinitionSchema]
    evidences: List[EvidenceDefinitionSchema]
