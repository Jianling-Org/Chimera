"""Input diagnostics for the fixed eight-worker Q3 measurement protocol."""
import json
from pathlib import Path


def read_json(path):
    path = Path(path)
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise ValueError(f"{path}: cannot read JSON: {error}") from error


def require_fields(record, fields, context):
    if not isinstance(record, dict):
        raise ValueError(f"{context}: expected a JSON object")
    missing = sorted(set(fields) - record.keys())
    if missing:
        raise ValueError(f"{context}: missing fields {missing}")
