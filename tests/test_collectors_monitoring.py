import logging

import pytest
import requests

from collectors import monitoring


@pytest.fixture(autouse=True)
def _isolated_alert_log(tmp_path, monkeypatch):
    """Every test gets its own alert log path and a clean logger — the
    module-level _alert_logger is otherwise process-global and would leak
    a FileHandler pointed at a previous test's tmp_path."""
    monkeypatch.setattr(monitoring, "ALERT_LOG_PATH", tmp_path / "pipeline-alerts.log")
    monitoring._alert_logger.handlers.clear()
    yield
    monitoring._alert_logger.handlers.clear()


def test_alert_writes_stage_tagged_line_to_log_file():
    monitoring.alert("kev", "run failed: RuntimeError: boom")

    contents = monitoring.ALERT_LOG_PATH.read_text()
    assert "[kev]" in contents
    assert "run failed: RuntimeError: boom" in contents


def test_alert_creates_log_directory_if_missing(tmp_path, monkeypatch):
    nested_path = tmp_path / "nested" / "pipeline-alerts.log"
    monkeypatch.setattr(monitoring, "ALERT_LOG_PATH", nested_path)

    monitoring.alert("verdict", "run failed")

    assert nested_path.exists()


def test_alert_never_raises_when_push_url_unreachable(monkeypatch):
    monkeypatch.setattr(monitoring, "PIPELINE_PUSH_URL", "http://kuma.example/api/push/abc")
    monkeypatch.setattr(
        monitoring.requests, "get", lambda *a, **k: (_ for _ in ()).throw(requests.ConnectionError())
    )
    monitoring.alert("cisco", "run failed")  # must not raise


def test_alert_pings_push_url_when_configured(monkeypatch):
    calls = []
    monkeypatch.setattr(monitoring, "PIPELINE_PUSH_URL", "http://kuma.example/api/push/abc")
    monkeypatch.setattr(
        monitoring.requests, "get", lambda url, params, timeout: calls.append((url, params))
    )

    monitoring.alert("msrc", "run failed")

    assert len(calls) == 1
    url, params = calls[0]
    assert url == "http://kuma.example/api/push/abc"
    assert params["status"] == "down"
    assert "msrc" in params["msg"]


def test_alert_skips_push_silently_when_no_push_url_configured(monkeypatch):
    monkeypatch.setattr(monitoring, "PIPELINE_PUSH_URL", None)
    monitoring.alert("fortinet", "run failed")  # must not raise, no requests.get call


def test_alert_logger_does_not_propagate_duplicate_file_handlers():
    monitoring.alert("precheck", "first")
    monitoring.alert("precheck", "second")

    file_handlers = [h for h in monitoring._alert_logger.handlers if isinstance(h, logging.FileHandler)]
    assert len(file_handlers) == 1
