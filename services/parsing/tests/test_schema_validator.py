import hashlib

from app.schema_validator import BaselineValidator


def test_schema_is_generated_from_shared_pydantic_model():
    schema = BaselineValidator().json_schema()
    assert "device" in schema["properties"]
    device_ref = schema["properties"]["device"]["$ref"]
    device_name = device_ref.rsplit("/", 1)[-1]
    assert "detected_vendor" in schema["$defs"][device_name]["properties"]


def test_valid_candidate():
    candidate = {
        "device": {
            "detected_vendor": "cisco",
            "config_sha256": hashlib.sha256(b"x").hexdigest(),
            "parsing_confidence": 0.9,
        }
    }
    result = BaselineValidator().validate(candidate)
    assert result.valid
    assert result.baseline is not None


def test_low_confidence_remains_valid_data():
    candidate = {
        "device": {
            "detected_vendor": "cisco",
            "config_sha256": hashlib.sha256(b"x").hexdigest(),
            "parsing_confidence": 0.42,
        }
    }
    result = BaselineValidator().validate(candidate)
    assert result.valid
    assert result.baseline.device.parsing_confidence == 0.42
