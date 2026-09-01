"""Decode an OTLP logs export into the fields a test can assert on.

Both editions export the same record, over two encodings: the agent's own
sender writes protobuf (OTLP/HTTP and OTLP/gRPC), the enterprise SIEM
connector writes the OTLP/JSON shape. A sink that matched substrings inside
the protobuf payload could prove an export arrived and nothing else - a
resource attribute, a severity number and a timestamp are all invisible to
it, and a record carrying 1970 as its time looked exactly like a correct one.

This module decodes both encodings into one normalised dict:

    {"format": "protobuf",
     "resource": {"service.name": "ebpfsentinel", ...},
     "scope": "ebpfsentinel",
     "records": [{"time_unix_nano": "1756...", "time_unix_seconds": 1756...,
                  "observed_time_unix_nano": "...", "observed_time_unix_seconds": ...,
                  "severity_number": 17, "severity_text": "high",
                  "body": "{\\"id\\":...}", "attributes": {"alert.rule_id": "..."}}]}

Timestamps are kept twice on purpose: the nanosecond value as a string,
because 19 digits do not survive a JSON parser using doubles, and the same
instant in seconds as a float, which is what a wall-clock comparison needs.

Protobuf is decoded by hand rather than through a generated stub, so the test
lane needs no python dependency: the wire format is tags and lengths, and the
message shapes are the ones the OpenTelemetry logs proto declares.
"""

import json
import struct

# ExportLogsServiceRequest
_REQUEST_RESOURCE_LOGS = 1
# ResourceLogs
_RESOURCE_LOGS_RESOURCE = 1
_RESOURCE_LOGS_SCOPE_LOGS = 2
# Resource
_RESOURCE_ATTRIBUTES = 1
# ScopeLogs
_SCOPE_LOGS_SCOPE = 1
_SCOPE_LOGS_RECORDS = 2
# InstrumentationScope
_SCOPE_NAME = 1
# LogRecord
_RECORD_TIME = 1
_RECORD_SEVERITY_NUMBER = 2
_RECORD_SEVERITY_TEXT = 3
_RECORD_BODY = 5
_RECORD_ATTRIBUTES = 6
_RECORD_OBSERVED_TIME = 11
# KeyValue
_KV_KEY = 1
_KV_VALUE = 2
# AnyValue
_ANY_STRING = 1
_ANY_BOOL = 2
_ANY_INT = 3
_ANY_DOUBLE = 4
_ANY_BYTES = 7

_NANOS_PER_SECOND = 1_000_000_000

class DecodeError(ValueError):
    """The payload is not an OTLP logs export this decoder understands."""

def _varint(buf, index):
    shift = 0
    value = 0
    while True:
        if index >= len(buf):
            raise DecodeError("truncated varint")
        byte = buf[index]
        index += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, index
        shift += 7
        if shift > 63:
            raise DecodeError("varint too long")

def _fields(buf):
    """Yield (field_number, wire_type, value) for every field in a message."""
    index = 0
    while index < len(buf):
        key, index = _varint(buf, index)
        number = key >> 3
        wire = key & 0x07
        if wire == 0:
            value, index = _varint(buf, index)
        elif wire == 1:
            value = struct.unpack_from("<Q", buf, index)[0]
            index += 8
        elif wire == 2:
            length, index = _varint(buf, index)
            value = buf[index:index + length]
            index += length
        elif wire == 5:
            value = struct.unpack_from("<I", buf, index)[0]
            index += 4
        else:
            raise DecodeError(f"unsupported wire type {wire}")
        yield number, wire, value

def _any_value(buf):
    for number, _wire, value in _fields(buf):
        if number == _ANY_STRING:
            return value.decode("utf-8", errors="replace")
        if number == _ANY_BOOL:
            return bool(value)
        if number == _ANY_INT:
            return value
        if number == _ANY_DOUBLE:
            return struct.unpack("<d", struct.pack("<Q", value))[0]
        if number == _ANY_BYTES:
            return value.decode("utf-8", errors="replace")
    return None

def _key_value(buf):
    key = None
    value = None
    for number, _wire, raw in _fields(buf):
        if number == _KV_KEY:
            key = raw.decode("utf-8", errors="replace")
        elif number == _KV_VALUE:
            value = _any_value(raw)
    return key, value

def _attributes(pairs):
    attributes = {}
    for buf in pairs:
        key, value = _key_value(buf)
        if key is not None:
            attributes[key] = value
    return attributes

def _stamp(entry, prefix, nanos):
    entry[f"{prefix}_unix_nano"] = str(nanos)
    entry[f"{prefix}_unix_seconds"] = round(nanos / _NANOS_PER_SECOND, 3)

def _protobuf_record(buf):
    entry = {
        "time_unix_nano": "0",
        "time_unix_seconds": 0.0,
        "observed_time_unix_nano": "0",
        "observed_time_unix_seconds": 0.0,
        "severity_number": 0,
        "severity_text": "",
        "body": "",
        "attributes": {},
    }
    attribute_bufs = []
    for number, _wire, value in _fields(buf):
        if number == _RECORD_TIME:
            _stamp(entry, "time", value)
        elif number == _RECORD_OBSERVED_TIME:
            _stamp(entry, "observed_time", value)
        elif number == _RECORD_SEVERITY_NUMBER:
            entry["severity_number"] = value
        elif number == _RECORD_SEVERITY_TEXT:
            entry["severity_text"] = value.decode("utf-8", errors="replace")
        elif number == _RECORD_BODY:
            body = _any_value(value)
            entry["body"] = body if isinstance(body, str) else json.dumps(body)
        elif number == _RECORD_ATTRIBUTES:
            attribute_bufs.append(value)
    entry["attributes"] = _attributes(attribute_bufs)
    return entry

def _decode_protobuf(body):
    resource = {}
    scope = ""
    records = []

    for number, _wire, resource_logs in _fields(body):
        if number != _REQUEST_RESOURCE_LOGS:
            continue
        for rl_number, _rl_wire, rl_value in _fields(resource_logs):
            if rl_number == _RESOURCE_LOGS_RESOURCE:
                attribute_bufs = [
                    raw
                    for r_number, _r_wire, raw in _fields(rl_value)
                    if r_number == _RESOURCE_ATTRIBUTES
                ]
                resource.update(_attributes(attribute_bufs))
            elif rl_number == _RESOURCE_LOGS_SCOPE_LOGS:
                for sl_number, _sl_wire, sl_value in _fields(rl_value):
                    if sl_number == _SCOPE_LOGS_SCOPE:
                        for s_number, _s_wire, s_value in _fields(sl_value):
                            if s_number == _SCOPE_NAME:
                                scope = s_value.decode("utf-8", errors="replace")
                    elif sl_number == _SCOPE_LOGS_RECORDS:
                        records.append(_protobuf_record(sl_value))

    return {"format": "protobuf", "resource": resource, "scope": scope, "records": records}

def _json_attributes(entries):
    attributes = {}
    for entry in entries or []:
        key = entry.get("key")
        if key is None:
            continue
        value = entry.get("value") or {}
        for name in ("stringValue", "boolValue", "intValue", "doubleValue", "bytesValue"):
            if name in value:
                attributes[key] = value[name]
                break
        else:
            attributes[key] = None
    return attributes

def _json_stamp(entry, prefix, raw):
    try:
        nanos = int(raw)
    except (TypeError, ValueError):
        nanos = 0
    _stamp(entry, prefix, nanos)

def _decode_json(body):
    payload = json.loads(body.decode("utf-8", errors="replace"))
    resource = {}
    scope = ""
    records = []

    for resource_logs in payload.get("resourceLogs") or []:
        resource.update(_json_attributes((resource_logs.get("resource") or {}).get("attributes")))
        for scope_logs in resource_logs.get("scopeLogs") or []:
            scope = (scope_logs.get("scope") or {}).get("name", scope)
            for record in scope_logs.get("logRecords") or []:
                entry = {
                    "severity_number": record.get("severityNumber", 0),
                    "severity_text": record.get("severityText", ""),
                    "body": (record.get("body") or {}).get("stringValue", ""),
                    "attributes": _json_attributes(record.get("attributes")),
                }
                _json_stamp(entry, "time", record.get("timeUnixNano"))
                _json_stamp(entry, "observed_time", record.get("observedTimeUnixNano"))
                records.append(entry)

    return {"format": "json", "resource": resource, "scope": scope, "records": records}

def decode_export(body, content_type=""):
    """Decode one export body, choosing the encoding by content type.

    A body that cannot be decoded raises rather than returning an empty
    export: a sink recording zero records for a payload it failed to read
    would make a broken decoder look like an agent that sent nothing.
    """
    if "json" in (content_type or "").lower():
        return _decode_json(body)
    return _decode_protobuf(body)
