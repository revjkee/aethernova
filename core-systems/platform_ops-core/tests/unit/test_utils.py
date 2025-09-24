import pytest
from llmops.utils import clean_text, normalize_prompt

def test_clean_text_removes_extra_spaces_and_newlines():
    input_text = "  Hello,  world! \n\n"
    expected = "Hello, world!"
    assert clean_text(input_text) == expected

def test_normalize_prompt_lowercases_and_trims():
    prompt = "  THIS is A Test PROMPT  "
    expected = "this is a test prompt"
    assert normalize_prompt(prompt) == expected

def test_clean_text_handles_empty_string():
    assert clean_text("") == ""

def test_normalize_prompt_handles_none():
    assert normalize_prompt(None) == ""

