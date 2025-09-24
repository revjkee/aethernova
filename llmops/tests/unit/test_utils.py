import pytest
from llmops.utils.text_cleaner import (
    normalize_text,
    remove_stopwords,
    strip_html_tags,
    filter_emoji,
    to_ascii_safe,
    remove_special_patterns
)
from llmops.validation.text_schema_validator import validate_clean_text

RAW_TEXTS = [
    ("<p>Hello World!</p>", "Hello World!"),
    ("Hello 😊🌍!", "Hello !"),
    ("Привет, мир!", "Привет, мир!"),
    ("This is a test...!!!", "This is a test..."),
    ("function(){ alert('XSS'); }", "function(){ alert('XSS'); }"),
    ("The quick brown fox jumps over the lazy dog.", "quick brown fox jumps lazy dog")
]

@pytest.mark.parametrize("raw,expected", [
    ("<h1>Title</h1>", "Title"),
    ("<script>alert(1)</script>", "alert(1)"),
    ("<div>Test</div>", "Test")
])
def test_strip_html_tags(raw, expected):
    cleaned = strip_html_tags(raw)
    assert cleaned == expected
    assert validate_clean_text(cleaned)

@pytest.mark.parametrize("text,expected", [
    ("This is a test sentence.", "test sentence"),
    ("The quick brown fox.", "quick brown fox"),
    ("It is what it is.", "what")
])
def test_remove_stopwords(text, expected):
    result = remove_stopwords(text)
    assert result == expected
    assert validate_clean_text(result)

@pytest.mark.parametrize("text,expected", [
    ("Hello 😊🌍", "Hello "),
    ("No emoji here", "No emoji here")
])
def test_filter_emoji(text, expected):
    filtered = filter_emoji(text)
    assert filtered == expected
    assert validate_clean_text(filtered)

@pytest.mark.parametrize("text,expected", [
    ("Café Münster", "Cafe Munster"),
    ("naïve façade", "naive facade"),
    ("über cool", "uber cool")
])
def test_ascii_conversion(text, expected):
    safe = to_ascii_safe(text)
    assert safe == expected
    assert validate_clean_text(safe)

@pytest.mark.parametrize("text,expected", [
    ("Contact: user@example.com", "Contact: "),
    ("Phone: +1-800-123-4567", "Phone: "),
    ("Visit https://example.com", "Visit ")
])
def test_remove_special_patterns(text, expected):
    result = remove_special_patterns(text)
    assert result == expected
    assert validate_clean_text(result)

def test_composite_pipeline():
    text = "<div>Hello 😊 from naïve user@example.com!</div>"
    result = strip_html_tags(text)
    result = filter_emoji(result)
    result = to_ascii_safe(result)
    result = remove_special_patterns(result)
    result = normalize_text(result)
    assert isinstance(result, str)
    assert "@" not in result
    assert "😊" not in result
    assert "<" not in result
    assert validate_clean_text(result)
