# -*- coding: utf-8 -*-
"""
Промышленные unit-тесты для zero_trust.session.session_manager.SessionManager.
Требования: стандартная библиотека Python (unittest, threading).
Запуск: python -m unittest zero-trust-core/tests/unit/test_session_manager.py
или из корня проекта: python -m unittest discover -s zero-trust-core/tests -t .
"""
import threading
import time
import unittest
from typing import List, Tuple

# Импорт тестируемого класса
from zero_trust.session.session_manager import SessionManager


class MockClock:
    """Детерминированные тесты времени."""
    def __init__(self, start: float = 1_700_000_000.0):
        self._t = float(start)
        self._lock = threading.Lock()

    def now(self) -> float:
        with self._lock:
            return self._t

    def advance(self, seconds: float) -> None:
        with self._lock:
            self._t += float(seconds)

    def back(self, seconds: float) -> None:
        with self._lock:
            self._t -= float(seconds)


def make_manager(clock: MockClock,
                 ttl_seconds: int = 5,
                 sliding: bool = True,
                 max_sessions: int = 100,
                 bind_fingerprint: bool = True,
                 bind_ip: bool = True) -> SessionManager:
    return SessionManager(
        hmac_key=b"supersecret-hmac-key-32bytes!!!",
        ttl_seconds=ttl_seconds,
        sliding=sliding,
        max_sessions=max_sessions,
        bind_fingerprint=bind_fingerprint,
        bind_ip=bind_ip,
        time_fn=clock.now,
    )


class SessionManagerIndustrialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = MockClock()
        self.mgr = make_manager(self.clock)

    # ---------------------- Базовые сценарии ----------------------

    def test_create_and_validate_success(self):
        tok = self.mgr.create_session(device_fingerprint="fp1", ip="1.2.3.4", meta={"user": "alice"})
        ok, reason, sess = self.mgr.validate(tok, device_fingerprint="fp1", ip="1.2.3.4")
        self.assertTrue(ok)
        self.assertEqual(reason, "ok")
        self.assertIsNotNone(sess)
        self.assertEqual(sess.meta.get("user"), "alice")
        self.assertEqual(self.mgr.count(), 1)

    def test_invalid_hmac_key_raises(self):
        with self.assertRaises(ValueError):
            SessionManager(hmac_key=b"short", ttl_seconds=5, time_fn=self.clock.now)

    # ---------------------- Подделки токена ----------------------

    def test_tamper_detection_any_change_breaks_validation(self):
        tok = self.mgr.create_session()
        # Мутации: изменим последний символ, добавим/удалим часть, испортим base64
        candidates = []
        # Изменение последнего символа
        candidates.append(tok[:-1] + ("A" if tok[-1] != "A" else "B"))
        # Удаление последнего сегмента (подписи)
        parts = tok.split(".")
        candidates.append(".".join(parts[:2]))
        # Добавление мусора
        candidates.append(tok + ".junk")
        # Порча первого сегмента
        candidates.append("!!" + ".".join(parts[1:]))

        for tampered in candidates:
            ok, reason, _ = self.mgr.validate(tampered)
            self.assertFalse(ok, msg=f"Token must be invalid: {tampered}")
            self.assertIn(reason, ("invalid_or_tampered", "malformed", "signature_mismatch", "mismatched_sid"))

    # ---------------------- Привязки к среде ----------------------

    def test_binding_enforced_when_enabled(self):
        tok = self.mgr.create_session(device_fingerprint="fpX", ip="10.0.0.1")
        # Неверный fingerprint
        ok, reason, _ = self.mgr.validate(tok, device_fingerprint="fpY", ip="10.0.0.1")
        self.assertFalse(ok)
        self.assertEqual(reason, "fingerprint_mismatch")
        # Неверный IP
        ok, reason, _ = self.mgr.validate(tok, device_fingerprint="fpX", ip="10.0.0.2")
        self.assertFalse(ok)
        self.assertEqual(reason, "ip_mismatch")
        # Оба параметра корректны
        ok, reason, _ = self.mgr.validate(tok, device_fingerprint="fpX", ip="10.0.0.1")
        self.assertTrue(ok)
        self.assertEqual(reason, "ok")

    def test_binding_disabled(self):
        mgr = make_manager(self.clock, bind_fingerprint=False, bind_ip=False)
        tok = mgr.create_session(device_fingerprint="fpX", ip="10.0.0.1")
        # Валидно даже при передаче других значений/отсутствии значений
        ok, reason, _ = mgr.validate(tok, device_fingerprint="other", ip="2.2.2.2")
        self.assertTrue(ok)
        self.assertEqual(reason, "ok")
        ok, reason, _ = mgr.validate(tok)
        self.assertTrue(ok)

    # ---------------------- TTL: скользящий и фиксированный ----------------------

    def test_expiration_with_sliding_window(self):
        tok = self.mgr.create_session()
        ok, _, s1 = self.mgr.validate(tok)
        self.assertTrue(ok)
        exp1 = s1.expires_ms
        # Через 3 секунды рефреш скользящего окна должен продлить срок
        self.clock.advance(3)
        ok, _, s2 = self.mgr.validate(tok)
        self.assertTrue(ok)
        self.assertGreater(s2.expires_ms, exp1)
        # Через ещё 6 секунд (итого 9) после продления токен всё ещё должен быть валиден
        self.clock.advance(6)
        ok, reason, _ = self.mgr.validate(tok)
        self.assertTrue(ok, msg=reason)

    def test_expiration_without_sliding_window(self):
        mgr = make_manager(self.clock, sliding=False, ttl_seconds=5)
        tok = mgr.create_session()
        ok, _, _ = mgr.validate(tok)
        self.assertTrue(ok)
        self.clock.advance(6)  # больше TTL
        ok, reason, _ = mgr.validate(tok)
        self.assertFalse(ok)
        self.assertEqual(reason, "expired")

    def test_backward_time_skew_does_not_break_validation(self):
        tok = self.mgr.create_session()
        ok, _, _ = self.mgr.validate(tok)
        self.assertTrue(ok)
        # Переведём время назад — не должно инвалидировать токен
        self.clock.back(4)
        ok, reason, _ = self.mgr.validate(tok)
        self.assertTrue(ok, msg=reason)

    # ---------------------- Ротация и инварианты ----------------------

    def test_rotation_increments_version_and_invalidates_old_token(self):
        tok = self.mgr.create_session()
        new_tok = self.mgr.rotate(tok)
        self.assertIsNotNone(new_tok)
        self.assertNotEqual(tok, new_tok)
        ok, reason, _ = self.mgr.validate(tok)
        self.assertFalse(ok)
        self.assertIn(reason, ("invalid_or_tampered", "revoked_or_missing"))
        ok, reason, s2 = self.mgr.validate(new_tok)
        self.assertTrue(ok)
        self.assertEqual(s2.version, 2)

    def test_rotation_invalid_token_returns_none(self):
        self.assertIsNone(self.mgr.rotate("not.a.real.token"))

    # ---------------------- Отзыв и удаление ----------------------

    def test_revocation_by_token_and_by_sid(self):
        tok = self.mgr.create_session()
        ok, _, s = self.mgr.validate(tok)
        self.assertTrue(ok)
        # Отзыв по токену
        self.assertTrue(self.mgr.revoke(tok))
        ok, reason, _ = self.mgr.validate(tok)
        self.assertFalse(ok)
        self.assertIn(reason, ("revoked_or_missing", "invalid_or_tampered"))
        # Новый токен и отзыв по SID
        tok2 = self.mgr.create_session()
        ok, _, s2 = self.mgr.validate(tok2)
        self.assertTrue(ok)
        self.assertTrue(self.mgr.revoke(s2.sid))
        ok, reason, _ = self.mgr.validate(tok2)
        self.assertFalse(ok)

    # ---------------------- Эвикция по емкости ----------------------

    def test_capacity_eviction_discards_least_recent(self):
        small_mgr = make_manager(self.clock, ttl_seconds=60, sliding=False, max_sessions=3, bind_fingerprint=False, bind_ip=False)
        tokens: List[str] = [small_mgr.create_session() for _ in range(3)]
        self.assertEqual(small_mgr.count(), 3)
        # Поддержим активность первого токена
        ok, _, _ = small_mgr.validate(tokens[0])
        self.assertTrue(ok)
        # Добавим 4-й — один должен быть вытеснен
        tokens.append(small_mgr.create_session())
        self.assertEqual(small_mgr.count(), 3)
        # Как минимум один из старых токенов станет невалиден
        invalids = [t for t in tokens if not small_mgr.validate(t)[0]]
        self.assertGreaterEqual(len(invalids), 1)

    # ---------------------- Экспорт/импорт состояния ----------------------

    def test_export_import_roundtrip_same_key_ok(self):
        tok = self.mgr.create_session(device_fingerprint="fp1", ip="1.1.1.1", meta={"k": "v"})
        ok, _, _ = self.mgr.validate(tok, device_fingerprint="fp1", ip="1.1.1.1")
        self.assertTrue(ok)
        state = self.mgr.export_state()
        # Импорт в новый менеджер с тем же ключом
        mgr2 = make_manager(self.clock)
        mgr2.import_state(state)
        ok, reason, s2 = mgr2.validate(tok, device_fingerprint="fp1", ip="1.1.1.1")
        self.assertTrue(ok, msg=reason)
        self.assertIsNotNone(s2)
        self.assertEqual(s2.meta.get("k"), "v")

    def test_export_import_with_different_key_fails_validation(self):
        tok = self.mgr.create_session()
        ok, _, _ = self.mgr.validate(tok)
        self.assertTrue(ok)
        state = self.mgr.export_state()
        # Новый ключ => подписи несовместимы => токен не валиден
        mgr2 = SessionManager(
            hmac_key=b"DIFFERENT-KEY-xxxxxxxxxxxxxxxxxxxxxxx",
            ttl_seconds=5,
            sliding=True,
            max_sessions=100,
            bind_fingerprint=True,
            bind_ip=True,
            time_fn=self.clock.now,
        )
        mgr2.import_state(state)  # само состояние импортировано, но подпись будет иной
        ok, reason, _ = mgr2.validate(tok)
        self.assertFalse(ok)
        self.assertIn(reason, ("invalid_or_tampered", "signature_mismatch", "mismatched_sid"))

    # ---------------------- Метрики ----------------------

    def test_metrics_counters_progress(self):
        base = self.mgr.metrics()
        self.assertEqual(base["active"], 0)
        t1 = self.mgr.create_session()
        t2 = self.mgr.create_session()
        ok, _, _ = self.mgr.validate(t1)
        self.assertTrue(ok)
        self.mgr.rotate(t1)
        self.mgr.revoke(t2)
        m = self.mgr.metrics()
        self.assertEqual(m["active"], 1)
        self.assertGreaterEqual(m["issued"], 2)
        self.assertGreaterEqual(m["validated"], 1)
        self.assertGreaterEqual(m["rotated"], 1)
        self.assertGreaterEqual(m["revoked"], 1)

    # ---------------------- Многопоточность ----------------------

    def test_thread_safety_under_load(self):
        threads = []
        tokens: List[str] = []
        lock = threading.Lock()
        barrier = threading.Barrier(16)

        def worker_create_validate_rotate():
            barrier.wait()
            t = self.mgr.create_session()
            with lock:
                tokens.append(t)
            ok, _, _ = self.mgr.validate(t)
            self.assertTrue(ok)
            # Ротация
            nt = self.mgr.rotate(t)
            self.assertIsNotNone(nt)
            ok, _, _ = self.mgr.validate(nt)
            self.assertTrue(ok)

        for _ in range(16):
            th = threading.Thread(target=worker_create_validate_rotate, daemon=True)
            threads.append(th)
            th.start()
        for th in threads:
            th.join(timeout=5)
            self.assertFalse(th.is_alive(), "Поток завис — возможна взаимоблокировка")

        # Все новые токены валидны, старые — нет
        valids = 0
        invalids = 0
        for t in tokens:
            ok, _, _ = self.mgr.validate(t)
            if ok:
                valids += 1
            else:
                invalids += 1
        self.assertGreaterEqual(invalids, 16)
        self.assertEqual(self.mgr.count(), 16)

    # ---------------------- Краевые случаи токенов ----------------------

    def test_malformed_token_structures(self):
        # Недостаточно сегментов
        ok, reason, _ = self.mgr.validate("only.one.part")
        self.assertFalse(ok)
        self.assertIn(reason, ("malformed", "invalid_or_tampered"))
        # Пустая строка
        ok, reason, _ = self.mgr.validate("")
        self.assertFalse(ok)
        # Лишние сегменты
        ok, reason, _ = self.mgr.validate("a.b.c.d")
        self.assertFalse(ok)

    def test_validate_after_expire_removes_session(self):
        mgr = make_manager(self.clock, ttl_seconds=1, sliding=False)
        tok = mgr.create_session()
        self.clock.advance(2)
        ok, reason, _ = mgr.validate(tok)
        self.assertFalse(ok)
        self.assertEqual(reason, "expired")
        # Повторная проверка уже не должна находить сессию
        ok2, reason2, _ = mgr.validate(tok)
        self.assertFalse(ok2)
        self.assertIn(reason2, ("invalid_or_tampered", "revoked_or_missing", "expired"))

    # ---------------------- Производительность (быстрый smoke) ----------------------

    def test_bulk_issue_and_validate_smoke(self):
        mgr = make_manager(self.clock, max_sessions=1000, ttl_seconds=30)
        toks: List[str] = [mgr.create_session() for _ in range(500)]
        # Быстрая валидация части токенов
        ok_count = sum(1 for t in toks[::5] if mgr.validate(t)[0])
        self.assertEqual(ok_count, len(toks[::5]))


if __name__ == "__main__":
    unittest.main()
