import pytest
from calibration.core.parameter_space import ParameterSpace, Parameter
from calibration.core.validator import ParameterValidationError

@pytest.fixture
def sample_parameters():
    return [
        Parameter(name="learning_rate", type="float", min=0.0001, max=0.1, default=0.01),
        Parameter(name="batch_size", type="int", min=8, max=512, default=64),
        Parameter(name="dropout", type="float", min=0.0, max=0.5, default=0.1),
        Parameter(name="optimizer", type="str", options=["adam", "sgd", "rmsprop"], default="adam")
    ]

def test_space_initialization(sample_parameters):
    space = ParameterSpace(parameters=sample_parameters)
    assert len(space.parameters) == 4
    assert space.get_default("batch_size") == 64

def test_parameter_sampling_within_bounds(sample_parameters):
    space = ParameterSpace(parameters=sample_parameters)
    sample = space.sample()

    assert 0.0001 <= sample["learning_rate"] <= 0.1
    assert 8 <= sample["batch_size"] <= 512
    assert 0.0 <= sample["dropout"] <= 0.5
    assert sample["optimizer"] in ["adam", "sgd", "rmsprop"]

def test_validation_of_valid_config(sample_parameters):
    space = ParameterSpace(parameters=sample_parameters)
    config = {
        "learning_rate": 0.005,
        "batch_size": 32,
        "dropout": 0.3,
        "optimizer": "sgd"
    }
    assert space.validate(config) is True

def test_validation_failure_out_of_bounds(sample_parameters):
    space = ParameterSpace(parameters=sample_parameters)
    config = {
        "learning_rate": 0.2,  # out of max bound
        "batch_size": 16,
        "dropout": 0.1,
        "optimizer": "adam"
    }
    with pytest.raises(ParameterValidationError):
        space.validate(config)

def test_validation_failure_invalid_choice(sample_parameters):
    space = ParameterSpace(parameters=sample_parameters)
    config = {
        "learning_rate": 0.01,
        "batch_size": 32,
        "dropout": 0.3,
        "optimizer": "unsupported_optimizer"
    }
    with pytest.raises(ParameterValidationError):
        space.validate(config)

def test_get_parameter_metadata(sample_parameters):
    space = ParameterSpace(parameters=sample_parameters)
    meta = space.describe("learning_rate")
    assert meta["type"] == "float"
    assert meta["min"] == 0.0001
    assert meta["default"] == 0.01

def test_list_all_parameters(sample_parameters):
    space = ParameterSpace(parameters=sample_parameters)
    names = space.list_names()
    assert sorted(names) == ["batch_size", "dropout", "learning_rate", "optimizer"]

def test_update_parameter_dynamic_constraints(sample_parameters):
    space = ParameterSpace(parameters=sample_parameters)
    space.update_constraints("batch_size", min=16, max=256)
    updated = space.describe("batch_size")
    assert updated["min"] == 16
    assert updated["max"] == 256

def test_reset_to_defaults(sample_parameters):
    space = ParameterSpace(parameters=sample_parameters)
    config = space.get_default_config()
    assert config == {
        "learning_rate": 0.01,
        "batch_size": 64,
        "dropout": 0.1,
        "optimizer": "adam"
    }

def test_invalid_parameter_definition_raises():
    with pytest.raises(ValueError):
        Parameter(name="invalid", type="unknown")

