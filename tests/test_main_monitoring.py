"""Tests for publisher/main.py's run_publisher_job orchestration — the
monitoring loop added by architecture review item 3: PAT-expiry preflight,
dead-man's-switch ping, and freshness check, wired around publisher.publish.run_once.
"""
from unittest.mock import patch

from publisher.main import run_publisher_job


def test_successful_run_pings_up_with_ok_when_everything_healthy():
    with (
        patch("publisher.main.run_once", return_value={"pushed": True}) as run_once,
        patch("publisher.main.check_token_expiry", return_value=None),
        patch("publisher.main.check_site_freshness", return_value=None),
        patch("publisher.main.ping_dead_mans_switch") as ping,
    ):
        run_publisher_job()

    run_once.assert_called_once()
    ping.assert_called_once_with(status="up", message="OK")


def test_publish_failure_pings_down_and_does_not_check_freshness():
    with (
        patch("publisher.main.run_once", side_effect=RuntimeError("push failed")),
        patch("publisher.main.check_token_expiry", return_value=None),
        patch("publisher.main.check_site_freshness") as freshness,
        patch("publisher.main.ping_dead_mans_switch") as ping,
    ):
        run_publisher_job()

    freshness.assert_not_called()
    ping.assert_called_once()
    _, kwargs = ping.call_args
    assert kwargs["status"] == "down"
    assert "Publisher run failed" in kwargs["message"]


def test_stale_site_after_successful_push_pings_down():
    with (
        patch("publisher.main.run_once", return_value={"pushed": True}),
        patch("publisher.main.check_token_expiry", return_value=None),
        patch(
            "publisher.main.check_site_freshness",
            return_value="Live site is stale: last generated ... 48:00:00 ago",
        ),
        patch("publisher.main.ping_dead_mans_switch") as ping,
    ):
        run_publisher_job()

    _, kwargs = ping.call_args
    assert kwargs["status"] == "down"
    assert "stale" in kwargs["message"]


def test_token_expiry_warning_on_success_still_pings_up():
    """A PAT-expiry warning alone (run otherwise healthy) should surface in
    the ping message but not flip the monitor to down -- that's what the
    urgent-window escalation is for, not the up/down status itself."""
    with (
        patch("publisher.main.run_once", return_value={"pushed": True}),
        patch(
            "publisher.main.check_token_expiry",
            return_value="WARNING: GITHUB_PUSH_TOKEN expires in 10 day(s)",
        ),
        patch("publisher.main.check_site_freshness", return_value=None),
        patch("publisher.main.ping_dead_mans_switch") as ping,
    ):
        run_publisher_job()

    _, kwargs = ping.call_args
    assert kwargs["status"] == "up"
    assert "expires in 10 day" in kwargs["message"]


def test_token_expiry_warning_included_in_failure_ping_message():
    with (
        patch("publisher.main.run_once", side_effect=RuntimeError("push failed")),
        patch(
            "publisher.main.check_token_expiry",
            return_value="URGENT: GITHUB_PUSH_TOKEN expires in 2 day(s)",
        ),
        patch("publisher.main.check_site_freshness") as freshness,
        patch("publisher.main.ping_dead_mans_switch") as ping,
    ):
        run_publisher_job()

    freshness.assert_not_called()
    _, kwargs = ping.call_args
    assert kwargs["status"] == "down"
    assert "Publisher run failed" in kwargs["message"]
    assert "URGENT" in kwargs["message"]


def test_run_publisher_job_never_raises_even_on_publish_failure():
    """run_publisher_job is invoked directly by APScheduler with no other
    guard -- it must never raise, or the entire scheduler loop dies."""
    with (
        patch("publisher.main.run_once", side_effect=RuntimeError("boom")),
        patch("publisher.main.check_token_expiry", return_value=None),
        patch("publisher.main.ping_dead_mans_switch"),
    ):
        run_publisher_job()  # should not raise
