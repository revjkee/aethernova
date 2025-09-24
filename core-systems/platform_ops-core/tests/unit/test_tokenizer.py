import pytest
from llmops.tokenizer import Tokenizer

@pytest.fixture
def tokenizer():
    return Tokenizer()

def test_tokenize_basic_words(tokenizer):
    text = "Hello world"
    expected_tokens = ["Hello", "world"]
    assert tokenizer.tokenize(text) == expected_tokens

def test_tokenize_with_punctuation(tokenizer):
    text = "Hello, world!"
    expected_tokens = ["Hello", ",", "world", "!"]
    assert tokenizer.tokenize(text) == expected_tokens

def test_detokenize_reverses_tokenize(tokenizer):
    text = "This is a test."
    tokens = tokenizer.tokenize(text)
    detokenized = tokenizer.detokenize(tokens)
    assert detokenized == text

def test_tokenize_empty_string(tokenizer):
    assert tokenizer.tokenize("") == []

def test_detokenize_empty_list(tokenizer):
    assert tokenizer.detokenize([]) == ""

def test_tokenize_handles_multiple_spaces(tokenizer):
    text = "Hello   world"
    expected_tokens = ["Hello", "world"]
    assert tokenizer.tokenize(text) == expected_tokens

