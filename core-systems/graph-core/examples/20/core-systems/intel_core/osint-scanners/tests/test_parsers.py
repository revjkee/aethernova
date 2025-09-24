"""
test_parsers.py
Юнит-тесты для модуля parsers OSINT-сканеров.

Проверяет корректность парсинга различных форматов данных,
обработка исключений и стабильность функций.
"""

import unittest
from datetime import datetime
from intel_core.osint_scanners.parsers.forum_parser import ForumParser
from intel_core.osint_scanners.parsers.social_media_parser import SocialMediaParser
from intel_core.osint_scanners.storage.models import ForumPost, SocialMediaPost, User

class TestForumParser(unittest.TestCase):
    def setUp(self):
        self.parser = ForumParser()

    def test_parse_valid_post(self):
        raw_post = {
            "post_id": "123",
            "username": "user1",
            "content": "This is a test post",
            "created_at": "2025-07-18T10:00:00Z",
            "url": "http://forum.example.com/post/123"
        }
        post = self.parser.parse(raw_post)
        self.assertIsInstance(post, ForumPost)
        self.assertEqual(post.post_id, "123")
        self.assertEqual(post.user.username, "user1")
        self.assertEqual(post.content, "This is a test post")
        self.assertEqual(post.url, "http://forum.example.com/post/123")
        self.assertIsInstance(post.created_at, datetime)

    def test_parse_invalid_post_raises(self):
        raw_post = {
            "post_id": None,
            "username": "user2",
            "content": "Missing post id",
            "created_at": "invalid-date"
        }
        with self.assertRaises(Exception):
            self.parser.parse(raw_post)

class TestSocialMediaParser(unittest.TestCase):
    def setUp(self):
        self.parser = SocialMediaParser()

    def test_parse_valid_post(self):
        raw_post = {
            "post_id": "sm_456",
            "username": "social_user",
            "content": "Hello from social media",
            "created_at": "2025-07-18T12:00:00Z",
            "platform": "Twitter",
            "url": "http://twitter.com/status/456"
        }
        post = self.parser.parse(raw_post)
        self.assertIsInstance(post, SocialMediaPost)
        self.assertEqual(post.post_id, "sm_456")
        self.assertEqual(post.user.username, "social_user")
        self.assertEqual(post.platform, "Twitter")

    def test_parse_missing_fields(self):
        raw_post = {
            "post_id": "sm_789",
            "content": "No username",
            "created_at": "2025-07-18T13:00:00Z",
            "platform": "Facebook"
        }
        post = self.parser.parse(raw_post)
        self.assertIsInstance(post, SocialMediaPost)
        self.assertIsNone(post.user.username)

if __name__ == "__main__":
    unittest.main()
