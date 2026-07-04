from unittest.mock import patch

from collectors.scheduler import (
    run_cisco_job,
    run_kev_job,
    run_msrc_job,
    run_precheck_job,
    run_verdict_job,
)


def test_kev_job_alerts_on_zero_feed_entries():
    with (
        patch("collectors.scheduler.run_kev", return_value={"feed_entry_count": 0}),
        patch("collectors.scheduler.alert") as alert,
    ):
        run_kev_job()
    alert.assert_called_once()
    stage, message = alert.call_args[0]
    assert stage == "kev"
    assert "zero" in message.lower()


def test_kev_job_does_not_alert_on_nonzero_feed_entries():
    with (
        patch("collectors.scheduler.run_kev", return_value={"feed_entry_count": 1300}),
        patch("collectors.scheduler.alert") as alert,
    ):
        run_kev_job()
    alert.assert_not_called()


def test_kev_job_alerts_on_exception_and_does_not_raise():
    with (
        patch("collectors.scheduler.run_kev", side_effect=RuntimeError("feed unreachable")),
        patch("collectors.scheduler.alert") as alert,
    ):
        run_kev_job()  # must not raise
    alert.assert_called_once()
    stage, message = alert.call_args[0]
    assert stage == "kev"
    assert "feed unreachable" in message


def test_msrc_job_alerts_on_exception():
    with (
        patch("collectors.scheduler.run_msrc", side_effect=RuntimeError("boom")),
        patch("collectors.scheduler.alert") as alert,
    ):
        run_msrc_job()
    alert.assert_called_once_with("msrc", "run failed: RuntimeError: boom")


def test_cisco_job_alerts_on_exception():
    with (
        patch("collectors.scheduler.run_cisco", side_effect=RuntimeError("boom")),
        patch("collectors.scheduler.alert") as alert,
    ):
        run_cisco_job()
    alert.assert_called_once_with("cisco", "run failed: RuntimeError: boom")


def test_precheck_job_alerts_on_exception():
    with (
        patch("collectors.scheduler.run_precheck", side_effect=RuntimeError("boom")),
        patch("collectors.scheduler.alert") as alert,
    ):
        run_precheck_job()
    alert.assert_called_once_with("precheck", "run failed: RuntimeError: boom")


def test_verdict_job_alerts_on_exception():
    with (
        patch("collectors.scheduler.run_verdict", side_effect=RuntimeError("boom")),
        patch("collectors.scheduler.alert") as alert,
    ):
        run_verdict_job()
    alert.assert_called_once_with("verdict", "run failed: RuntimeError: boom")
