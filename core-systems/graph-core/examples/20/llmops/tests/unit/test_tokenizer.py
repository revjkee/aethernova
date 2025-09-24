import pytest
from llmops.tokenization.tokenizer import PromptTokenizer
from llmops.tokenization.token_schema_validator import validate_token_schema
from llmops.security.token_filter import contains_unsafe_tokens

SIMPLE_CASES = [
    ("What is AI?", ["What", "is", "AI", "?"]),
    ("Translate to French: Hello", ["Translate", "to", "French", ":", "Hello"]),
    ("42 + 8 = ?", ["42", "+", "8", "=", "?"])
]

UNICODE_CASES = [
    ("你好，世界", ["你", "好", "，", "世", "界"]),
    ("¿Cómo estás?", ["¿", "Cómo", "estás", "?"]),
    ("Привет мир", ["Привет", "мир"])
]

MALICIOUS_CASES = [
    ("<script>alert(1)</script>", True),
    ("DROP TABLE users;", True),
    ("echo 'safe'", False)
]

@pytest.fixture(scope="module")
def tokenizer():
    return PromptTokenizer(language="auto", split_mode="semantic")

def test_basic_tokenization(tokenizer):
    for text, expected in SIMPLE_CASES:
        tokens = tokenizer.tokenize(text)
        assert tokens == expected
        assert isinstance(tokens, list)
        assert all(isinstance(tok, str) for tok in tokens)
        assert validate_token_schema(tokens)

def test_unicode_tokenization(tokenizer):
    for text, expected in UNICODE_CASES:
        tokens = tokenizer.tokenize(text)
        assert tokens == expected
        assert validate_token_schema(tokens)

def test_tokenizer_output_integrity(tokenizer):
    text = "Deep learning is revolutionizing medicine."
    tokens = tokenizer.tokenize(text)
    assert len(tokens) >= 5
    reconstructed = tokenizer.detokenize(tokens)
    assert isinstance(reconstructed, str)
    assert len(reconstructed) > 0
    assert text.lower().replace(".", "") in reconstructed.lower()

def test_token_length_and_type(tokenizer):
    tokens = tokenizer.tokenize("Test 123 😊 🚀")
    for tok in tokens:
        assert isinstance(tok, str)
        assert 0 < len(tok) <= 64  # enforce max token unit
        assert not isinstance(tok, bytes)

def test_malicious_token_detection():
    for text, should_detect in MALICIOUS_CASES:
        tokens = PromptTokenizer().tokenize(text)
        flagged = contains_unsafe_tokens(tokens)
        assert flagged == should_detect
