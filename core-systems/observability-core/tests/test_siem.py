import logging

from observability_core.handlers.siem_router import SIEMRouterHandler


def make_record(level: int, **extra) -> logging.LogRecord:
    record = logging.LogRecord(
        name="security",
        level=level,
        pathname=__file__,
        lineno=10,
        msg="security event",
        args=(),
        exc_info=None,
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def test_siem_router_uses_injected_targets_and_fallback() -> None:
    routed: list[tuple[str, dict]] = []

    def failing(_: dict) -> None:
        raise RuntimeError("unavailable")

    handler = SIEMRouterHandler(
        {
            "xdr": failing,
            "splunk": lambda event: routed.append(("splunk", event)),
            "sentinel": lambda event: routed.append(("sentinel", event)),
            "elk": lambda event: routed.append(("elk", event)),
        },
        fallback={"xdr": "elk"},
    )

    handler.emit(make_record(logging.CRITICAL, security_tag="exploit_attempt"))

    targets = [target for target, _ in routed]
    assert targets == ["elk", "splunk", "sentinel"]
    assert all(event["threat_score"] == 90 for _, event in routed)


def test_siem_router_ignores_non_security_info_records() -> None:
    routed: list[dict] = []
    handler = SIEMRouterHandler({"elk": routed.append})

    handler.emit(make_record(logging.INFO))

    assert routed == []
