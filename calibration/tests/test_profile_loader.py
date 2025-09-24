import pytest
import tempfile
import yaml
import os

from calibration.presets import profile_loader
from calibration.core.validator import ParameterValidationError

@pytest.fixture
def valid_profile():
    return {
        "learning_rate": 0.01,
        "batch_size": 64,
        "optimizer": "adam",
        "dropout": 0.1
    }

@pytest.fixture
def invalid_profile_type():
    return {
        "learning_rate": "very fast",  # invalid type
        "batch_size": 64,
        "optimizer": "adam",
        "dropout": 0.1
    }

@pytest.fixture
def invalid_profile_value():
    return {
        "learning_rate": 0.01,
        "batch_size": 10000,  # out of expected range
        "optimizer": "adam",
        "dropout": 0.1
    }

def write_temp_yaml(data):
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".yaml", delete=False) as f:
        yaml.dump(data, f)
        return f.name

def test_load_valid_yaml_profile(valid_profile):
    path = write_temp_yaml(valid_profile)
    profile = profile_loader.load_profile(path)
    assert isinstance(profile, dict)
    assert profile["batch_size"] == 64
    os.remove(path)

def test_load_profile_and_validate(valid_profile):
    path = write_temp_yaml(valid_profile)
    result = profile_loader.load_and_validate(path)
    assert result["optimizer"] == "adam"
    os.remove(path)

def test_load_invalid_type_raises(invalid_profile_type):
    path = write_temp_yaml(invalid_profile_type)
    with pytest.raises(ParameterValidationError):
        profile_loader.load_and_validate(path)
    os.remove(path)

def test_load_invalid_value_raises(invalid_profile_value):
    path = write_temp_yaml(invalid_profile_value)
    with pytest.raises(ParameterValidationError):
        profile_loader.load_and_validate(path)
    os.remove(path)

def test_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        profile_loader.load_profile("non_existent.yaml")

def test_corrupted_yaml_raises():
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".yaml", delete=False) as f:
        f.write("bad: [unclosed")
        path = f.name

    with pytest.raises(yaml.YAMLError):
        profile_loader.load_profile(path)

    os.remove(path)

def test_empty_yaml_returns_empty_dict():
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".yaml", delete=False) as f:
        f.write("")
        path = f.name

    result = profile_loader.load_profile(path)
    assert result == {}
    os.remove(path)

