#!/usr/bin/env python3
"""Collect system metrics, log them, and optionally send SMTP alerts."""

from __future__ import annotations

import argparse
import json
import os
import re
import smtplib
import ssl
import sys
import time
import traceback
from collections.abc import Sequence
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import psutil

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = SCRIPT_DIR / "config.json"
DEFAULT_MAX_LOG_BYTES = 5_000_000
DEFAULT_BACKUP_COUNT = 3


class ConfigError(ValueError):
    """Raised when the configuration file is missing or invalid."""


def _number(
    config: dict[str, Any],
    key: str,
    default: float,
    *,
    minimum: float,
    maximum: float | None = None,
) -> float:
    value = config.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"'{key}' must be a number")
    if value < minimum or (maximum is not None and value > maximum):
        limit = (
            f" between {minimum} and {maximum}"
            if maximum is not None
            else f" >= {minimum}"
        )
        raise ConfigError(f"'{key}' must be{limit}")
    return float(value)


def _integer(
    config: dict[str, Any],
    key: str,
    default: int,
    *,
    minimum: int,
    maximum: int | None = None,
) -> int:
    value = config.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"'{key}' must be an integer")
    if value < minimum or (maximum is not None and value > maximum):
        limit = (
            f" between {minimum} and {maximum}"
            if maximum is not None
            else f" >= {minimum}"
        )
        raise ConfigError(f"'{key}' must be{limit}")
    return value


def validate_config(raw_config: Any, config_dir: Path) -> dict[str, Any]:
    """Validate and normalize configuration values."""
    if not isinstance(raw_config, dict):
        raise ConfigError("the top-level configuration must be a JSON object")

    config = dict(raw_config)

    log_dir_value = config.get("log_dir")
    if not isinstance(log_dir_value, str) or not log_dir_value.strip():
        raise ConfigError("'log_dir' is required and must be a non-empty string")
    log_dir = Path(os.path.expandvars(log_dir_value)).expanduser()
    if not log_dir.is_absolute():
        log_dir = config_dir / log_dir
    config["log_dir"] = str(log_dir.resolve())

    disk_mount = config.get("disk_mount", "/")
    if not isinstance(disk_mount, str) or not disk_mount.strip():
        raise ConfigError("'disk_mount' must be a non-empty string")
    config["disk_mount"] = disk_mount

    config["cpu_threshold"] = _number(
        config, "cpu_threshold", 80, minimum=0, maximum=100
    )
    config["mem_threshold"] = _number(
        config, "mem_threshold", 80, minimum=0, maximum=100
    )
    config["disk_threshold"] = _number(
        config, "disk_threshold", 90, minimum=0, maximum=100
    )
    config["net_threshold_kbps"] = _number(
        config, "net_threshold_kbps", 10_240, minimum=0
    )
    config["max_log_bytes"] = _integer(
        config,
        "max_log_bytes",
        DEFAULT_MAX_LOG_BYTES,
        minimum=0,
    )
    config["backup_count"] = _integer(
        config,
        "backup_count",
        DEFAULT_BACKUP_COUNT,
        minimum=0,
        maximum=100,
    )

    smtp = config.get("smtp", {})
    if not isinstance(smtp, dict):
        raise ConfigError("'smtp' must be a JSON object")
    smtp = dict(smtp)
    enabled = smtp.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ConfigError("'smtp.enabled' must be true or false")
    smtp["enabled"] = enabled

    if enabled:
        for key in ("host", "sender_email", "receiver_email"):
            value = smtp.get(key)
            if (
                not isinstance(value, str)
                or not value.strip()
                or "\n" in value
                or "\r" in value
            ):
                raise ConfigError(
                    f"'smtp.{key}' must be a non-empty, single-line string "
                    "when SMTP is enabled"
                )

        port = smtp.get("port", 587)
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65_535
        ):
            raise ConfigError("'smtp.port' must be an integer between 1 and 65535")
        smtp["port"] = port

        security = smtp.get("security", "starttls")
        if security not in {"starttls", "ssl", "none"}:
            raise ConfigError("'smtp.security' must be 'starttls', 'ssl', or 'none'")
        smtp["security"] = security

        timeout = smtp.get("timeout_seconds", 15)
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or timeout <= 0
        ):
            raise ConfigError("'smtp.timeout_seconds' must be a positive number")
        smtp["timeout_seconds"] = float(timeout)

        password_env = smtp.get("password_env", "SYSMON_EMAIL_PASSWORD")
        if not isinstance(password_env, str) or not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*", password_env
        ):
            raise ConfigError("'smtp.password_env' must be a valid environment name")
        smtp["password_env"] = password_env

        subject_prefix = smtp.get("subject_prefix", "[SysMon]")
        if (
            not isinstance(subject_prefix, str)
            or "\n" in subject_prefix
            or "\r" in subject_prefix
        ):
            raise ConfigError("'smtp.subject_prefix' must be a single-line string")
        smtp["subject_prefix"] = subject_prefix

        username = smtp.get("username", smtp["sender_email"])
        if (
            not isinstance(username, str)
            or not username.strip()
            or "\n" in username
            or "\r" in username
        ):
            raise ConfigError("'smtp.username' must be a non-empty, single-line string")
        smtp["username"] = username

    config["smtp"] = smtp
    return config


def load_config(config_path: str | Path | None = None) -> dict[str, Any]:
    """Load, validate, and normalize a JSON configuration file."""
    path = Path(config_path) if config_path is not None else DEFAULT_CONFIG_PATH
    path = path.expanduser().resolve()

    if not path.is_file():
        raise ConfigError(
            f"config file not found: {path}. Create it from config.example.json"
        )

    try:
        with path.open("r", encoding="utf-8") as config_file:
            raw_config = json.load(config_file)
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"invalid JSON in {path} at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    except OSError as exc:
        raise ConfigError(f"could not read config file {path}: {exc}") from exc

    return validate_config(raw_config, path.parent)


def ensure_log_dir(log_dir: Path) -> None:
    """Create the log directory if necessary."""
    log_dir.mkdir(parents=True, exist_ok=True)


def _rotate_log(
    log_file: Path, max_bytes: int, backup_count: int, incoming: int
) -> None:
    if max_bytes == 0 or not log_file.exists():
        return
    if log_file.stat().st_size + incoming <= max_bytes:
        return

    if backup_count == 0:
        log_file.unlink()
        return

    oldest = log_file.with_name(f"{log_file.name}.{backup_count}")
    oldest.unlink(missing_ok=True)
    for number in range(backup_count - 1, 0, -1):
        source = log_file.with_name(f"{log_file.name}.{number}")
        if source.exists():
            source.replace(log_file.with_name(f"{log_file.name}.{number + 1}"))
    log_file.replace(log_file.with_name(f"{log_file.name}.1"))


def log_message(
    log_dir: Path,
    message: str,
    filename: str = "sysmon.log",
    *,
    max_bytes: int = DEFAULT_MAX_LOG_BYTES,
    backup_count: int = DEFAULT_BACKUP_COUNT,
) -> None:
    """Append a timestamped message and rotate the file when configured."""
    ensure_log_dir(log_dir)
    log_file = log_dir / filename
    now = datetime.now().astimezone().isoformat(timespec="seconds")
    line = f"[{now}] {message}\n"
    encoded_size = len(line.encode("utf-8"))
    _rotate_log(log_file, max_bytes, backup_count, encoded_size)
    with log_file.open("a", encoding="utf-8") as file_handle:
        file_handle.write(line)


def _write_json_atomic(path: Path, value: dict[str, float | int]) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as state_file:
            json.dump(value, state_file)
            state_file.flush()
            os.fsync(state_file.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def get_network_rate(log_dir: Path) -> float | None:
    """Return total network throughput in decimal kilobits/second since the last run."""
    ensure_log_dir(log_dir)
    state_file = log_dir / "net_state.json"
    counters = psutil.net_io_counters(pernic=False)
    if counters is None:
        return None

    now_ts = time.time()
    current: dict[str, float | int] = {
        "bytes_sent": counters.bytes_sent,
        "bytes_recv": counters.bytes_recv,
        "timestamp": now_ts,
    }

    previous: Any = None
    try:
        with state_file.open("r", encoding="utf-8") as state_handle:
            previous = json.load(state_handle)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass

    _write_json_atomic(state_file, current)

    if not isinstance(previous, dict):
        return None
    try:
        elapsed = now_ts - float(previous["timestamp"])
        sent_delta = max(0, counters.bytes_sent - int(previous["bytes_sent"]))
        received_delta = max(0, counters.bytes_recv - int(previous["bytes_recv"]))
    except (KeyError, TypeError, ValueError):
        return None
    if elapsed <= 0:
        return None

    return ((sent_delta + received_delta) * 8) / elapsed / 1000


def collect_metrics(config: dict[str, Any]) -> dict[str, float | None]:
    """Collect CPU, memory, disk, and network metrics."""
    log_dir = Path(config["log_dir"])
    metrics: dict[str, float | None] = {
        "cpu_percent": psutil.cpu_percent(interval=1),
        "mem_percent": psutil.virtual_memory().percent,
        "disk_percent": psutil.disk_usage(config["disk_mount"]).percent,
        "net_kbps": get_network_rate(log_dir),
    }
    return metrics


def check_thresholds(
    config: dict[str, Any], metrics: dict[str, float | None]
) -> list[str]:
    """Return alert messages for metrics strictly above their thresholds."""
    checks = (
        ("cpu_percent", "cpu_threshold", "High CPU usage", "%"),
        ("mem_percent", "mem_threshold", "High memory usage", "%"),
        ("disk_percent", "disk_threshold", "High disk usage", "%"),
        ("net_kbps", "net_threshold_kbps", "High network throughput", " kbps"),
    )
    alerts: list[str] = []
    for metric_key, threshold_key, label, unit in checks:
        value = metrics[metric_key]
        threshold = config[threshold_key]
        if value is not None and value > threshold:
            alerts.append(f"{label}: {value:.1f}{unit} (threshold {threshold:g}{unit})")
    return alerts


def format_metrics(metrics: dict[str, float | None]) -> str:
    """Format metrics as one human-readable log line."""
    net_value = metrics["net_kbps"]
    net_text = f"{net_value:.1f} kbps" if net_value is not None else "N/A"
    return (
        f"CPU={metrics['cpu_percent']:.1f}%, "
        f"MEM={metrics['mem_percent']:.1f}%, "
        f"DISK={metrics['disk_percent']:.1f}%, "
        f"NET={net_text}"
    )


def send_email_alert(
    config: dict[str, Any],
    metrics: dict[str, float | None],
    alerts: Sequence[str],
) -> str:
    """Send an SMTP alert and return a status message for the log."""
    smtp_config = config["smtp"]
    if not smtp_config.get("enabled", False):
        return "Email not sent: SMTP alerts are disabled."

    password_env = smtp_config["password_env"]
    password = os.environ.get(password_env)
    if not password:
        return f"Email not sent: environment variable {password_env} is not set."

    message = EmailMessage()
    message["From"] = smtp_config["sender_email"]
    message["To"] = smtp_config["receiver_email"]
    message["Subject"] = (
        f"{smtp_config['subject_prefix']} ALERT - {len(alerts)} issue(s) detected"
    )
    alert_body = "\n".join(f"- {alert}" for alert in alerts)
    message.set_content(
        "SysMon detected the following issue(s):\n\n"
        f"{alert_body}\n\n"
        f"Current metrics:\n{format_metrics(metrics)}\n\n"
        f"Timestamp: {datetime.now().astimezone().isoformat(timespec='seconds')}\n"
    )

    host = smtp_config["host"]
    port = smtp_config["port"]
    timeout = smtp_config["timeout_seconds"]
    security = smtp_config["security"]
    context = ssl.create_default_context()

    try:
        if security == "ssl":
            client: smtplib.SMTP = smtplib.SMTP_SSL(
                host, port, timeout=timeout, context=context
            )
        else:
            client = smtplib.SMTP(host, port, timeout=timeout)

        with client as server:
            if security == "starttls":
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
            server.login(smtp_config["username"], password)
            server.send_message(message)
        return "Email alert sent successfully."
    except (OSError, smtplib.SMTPException) as exc:
        return f"Failed to send email alert: {exc}"


def run_monitor(
    config: dict[str, Any], *, send_email: bool = True
) -> tuple[dict[str, float | None], list[str], str | None]:
    """Run one monitoring cycle."""
    log_dir = Path(config["log_dir"])
    max_bytes = config["max_log_bytes"]
    backup_count = config["backup_count"]
    metrics = collect_metrics(config)
    metrics_text = format_metrics(metrics)
    log_message(
        log_dir,
        f"METRICS: {metrics_text}",
        max_bytes=max_bytes,
        backup_count=backup_count,
    )

    alerts = check_thresholds(config, metrics)
    for alert in alerts:
        log_message(
            log_dir,
            f"ALERT: {alert}",
            max_bytes=max_bytes,
            backup_count=backup_count,
        )
        log_message(
            log_dir,
            f"ALERT: {alert}",
            filename="alerts.log",
            max_bytes=max_bytes,
            backup_count=backup_count,
        )

    email_result: str | None = None
    if alerts:
        email_result = (
            send_email_alert(config, metrics, alerts)
            if send_email
            else "Email not sent: disabled by --no-email."
        )
        log_message(
            log_dir,
            email_result,
            max_bytes=max_bytes,
            backup_count=backup_count,
        )

    return metrics, alerts, email_result


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect system metrics and send threshold alerts."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help=f"configuration file (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="validate configuration and exit without collecting metrics",
    )
    parser.add_argument(
        "--no-email",
        action="store_true",
        help="collect and log alerts without sending email",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point."""
    args = build_argument_parser().parse_args(argv)
    config: dict[str, Any] | None = None
    try:
        config = load_config(args.config)
        if args.check_config:
            print(f"Configuration is valid: {Path(args.config).expanduser().resolve()}")
            return 0

        metrics, alerts, email_result = run_monitor(
            config, send_email=not args.no_email
        )
        print(f"METRICS: {format_metrics(metrics)}")
        for alert in alerts:
            print(f"ALERT: {alert}")
        if email_result:
            print(email_result)
        return 0
    except Exception as exc:  # noqa: BLE001 - CLI boundary must return a failure code.
        error_message = f"{type(exc).__name__}: {exc}"
        print(f"SysMon failed: {error_message}", file=sys.stderr)
        if config is not None:
            try:
                log_message(
                    Path(config["log_dir"]),
                    f"ERROR: {error_message}\n{traceback.format_exc()}",
                    filename="errors.log",
                    max_bytes=config["max_log_bytes"],
                    backup_count=config["backup_count"],
                )
            except Exception as log_error:  # noqa: BLE001 - preserve the primary error.
                print(f"Could not write error log: {log_error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
