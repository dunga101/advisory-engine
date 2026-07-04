import json
import threading
from datetime import date, datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import Mock, patch

import pytest
import requests

from publisher.config import TOKEN_EXPIRES, TOKEN_EXPIRY_URGENT_DAYS, TOKEN_EXPIRY_WARN_DAYS
from publisher.monitoring import check_site_freshness, check_token_expiry, ping_dead_mans_switch

# --- check_token_expiry ---


def test_token_expiry_none_when_far_out():
    today = TOKEN_EXPIRES - timedelta(days=TOKEN_EXPIRY_WARN_DAYS + 1)
    assert check_token_expiry(today=today) is None


def test_token_expiry_warns_inside_warn_window():
    today = TOKEN_EXPIRES - timedelta(days=TOKEN_EXPIRY_WARN_DAYS - 1)
    message = check_token_expiry(today=today)
    assert message is not None
    assert "WARNING" in message
    assert "URGENT" not in message


def test_token_expiry_escalates_inside_urgent_window():
    today = TOKEN_EXPIRES - timedelta(days=TOKEN_EXPIRY_URGENT_DAYS - 1)
    message = check_token_expiry(today=today)
    assert "URGENT" in message


def test_token_expiry_escalates_on_exact_urgent_boundary():
    today = TOKEN_EXPIRES - timedelta(days=TOKEN_EXPIRY_URGENT_DAYS)
    assert "URGENT" in check_token_expiry(today=today)


def test_token_expiry_urgent_after_expiry():
    today = TOKEN_EXPIRES + timedelta(days=1)
    message = check_token_expiry(today=today)
    assert "URGENT" in message


def test_token_expiry_warns_on_exact_warn_boundary():
    # Exactly WARN_DAYS out is inclusive -- the warning window starts here.
    today = TOKEN_EXPIRES - timedelta(days=TOKEN_EXPIRY_WARN_DAYS)
    assert check_token_expiry(today=today) is not None


# --- ping_dead_mans_switch ---


def test_ping_skips_silently_when_no_push_url_configured():
    # Must never raise -- monitoring must never break a publish run.
    ping_dead_mans_switch(None, status="up", message="OK")


def test_ping_sends_status_and_message_as_query_params():
    with patch("publisher.monitoring.requests.get") as get:
        ping_dead_mans_switch("http://kuma.example/api/push/abc123", status="down", message="boom")
    get.assert_called_once()
    args, kwargs = get.call_args
    assert args[0] == "http://kuma.example/api/push/abc123"
    assert kwargs["params"] == {"status": "down", "msg": "boom"}


def test_ping_never_raises_on_network_failure():
    with patch(
        "publisher.monitoring.requests.get", side_effect=requests.ConnectionError("refused")
    ):
        ping_dead_mans_switch("http://kuma.example/api/push/abc123", status="up", message="OK")


# --- check_site_freshness ---


def test_freshness_skips_when_no_status_url_configured():
    message = check_site_freshness(None)
    assert message is not None
    assert "not configured" in message


def test_freshness_none_when_recently_generated():
    now = datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc)
    fake_response = Mock()
    fake_response.json.return_value = {"generated_at": "2026-07-01T04:00:00+00:00"}
    fake_response.raise_for_status.return_value = None
    with patch("publisher.monitoring.requests.get", return_value=fake_response):
        assert check_site_freshness("http://site.example/status.json", now=now) is None


def test_freshness_warns_when_stale_beyond_threshold():
    now = datetime(2026, 7, 3, 12, 0, tzinfo=timezone.utc)
    fake_response = Mock()
    fake_response.json.return_value = {"generated_at": "2026-07-01T04:00:00+00:00"}
    fake_response.raise_for_status.return_value = None
    with patch("publisher.monitoring.requests.get", return_value=fake_response):
        message = check_site_freshness("http://site.example/status.json", now=now)
    assert message is not None
    assert "stale" in message


def test_freshness_reports_failure_when_site_unreachable():
    with patch(
        "publisher.monitoring.requests.get", side_effect=requests.ConnectionError("refused")
    ):
        message = check_site_freshness("http://site.example/status.json")
    assert message is not None
    assert "failed" in message


def test_freshness_reports_failure_on_non_2xx():
    fake_response = Mock()
    fake_response.raise_for_status.side_effect = requests.HTTPError("500 server error")
    with patch("publisher.monitoring.requests.get", return_value=fake_response):
        message = check_site_freshness("http://site.example/status.json")
    assert message is not None
    assert "failed" in message


# --- Real local HTTP server: genuine end-to-end proof, not just mocks ---


class _RecordingPushHandler(BaseHTTPRequestHandler):
    received: list[dict] = []

    def do_GET(self):
        from urllib.parse import parse_qs, urlparse

        query = parse_qs(urlparse(self.path).query)
        self.__class__.received.append({k: v[0] for k, v in query.items()})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, format, *args):  # noqa: A002 - silence test server logging
        pass


@pytest.fixture
def push_server():
    _RecordingPushHandler.received = []
    server = HTTPServer(("127.0.0.1", 0), _RecordingPushHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, f"http://127.0.0.1:{server.server_port}/api/push/test-token"
    server.shutdown()
    thread.join(timeout=5)


def test_ping_dead_mans_switch_real_http_round_trip_on_success(push_server):
    server, url = push_server
    ping_dead_mans_switch(url, status="up", message="OK")
    assert _RecordingPushHandler.received == [{"status": "up", "msg": "OK"}]


def test_ping_dead_mans_switch_real_http_round_trip_on_simulated_failure(push_server):
    """Simulates the exact scenario the review asked to verify end-to-end:
    a failed publish run should result in a 'down' ping actually reaching
    the monitor, not just a code path that looks right on paper."""
    server, url = push_server
    ping_dead_mans_switch(url, status="down", message="Publisher run failed: GitPublishError")
    assert _RecordingPushHandler.received == [
        {"status": "down", "msg": "Publisher run failed: GitPublishError"}
    ]


class _StatusJsonHandler(BaseHTTPRequestHandler):
    body = b"{}"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(self.__class__.body)

    def log_message(self, format, *args):  # noqa: A002
        pass


@pytest.fixture
def status_server():
    server = HTTPServer(("127.0.0.1", 0), _StatusJsonHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join(timeout=5)


def test_check_site_freshness_real_http_fresh_site(status_server):
    now = datetime.now(timezone.utc)
    _StatusJsonHandler.body = json.dumps({"generated_at": now.isoformat()}).encode()
    url = f"http://127.0.0.1:{status_server.server_port}/status.json"
    assert check_site_freshness(url, now=now) is None


def test_check_site_freshness_real_http_stale_site(status_server):
    now = datetime.now(timezone.utc)
    stale = now - timedelta(hours=48)
    _StatusJsonHandler.body = json.dumps({"generated_at": stale.isoformat()}).encode()
    url = f"http://127.0.0.1:{status_server.server_port}/status.json"
    message = check_site_freshness(url, now=now)
    assert message is not None
    assert "stale" in message
