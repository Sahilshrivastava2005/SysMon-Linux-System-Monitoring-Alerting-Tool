# SysMon — Linux System Monitoring and Alerting

SysMon is a small Python command-line monitor for CPU, memory, disk, and total
network throughput. Each run writes timestamped metrics to rotating log files.
When a configured threshold is exceeded, SysMon records an alert and can send it
through SMTP. It is designed for one-shot execution from cron or a systemd timer.

## Features

- CPU, memory, disk, and aggregate network-throughput monitoring
- Validated JSON configuration with clear startup errors
- Size-based rotation for metric, alert, and error logs
- STARTTLS, implicit TLS, or plain SMTP transport
- Email credentials read from an environment variable, never from JSON
- Nonzero exit status on configuration or runtime failure
- A cron-safe launcher that automatically uses the project virtual environment
- Unit tests for configuration, thresholds, network rates, logging, and email

## Requirements

- Linux (the code also works on macOS, but cron examples target Linux)
- Python 3.10 or newer
- `psutil` (installed from `requirements.txt`)

## Project layout

```text
SysMon-main/
├── sysmon.py
├── run_sysmon.sh
├── config.example.json
├── requirements.txt
├── tests/
└── README.md
```

`config.json`, `.venv/`, and `logs/` are intentionally ignored by Git.

## Installation

Run these commands from the project directory:

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install -r requirements.txt
cp config.example.json config.json
chmod +x run_sysmon.sh
```

The example configuration writes to `./logs`. Relative `log_dir` values are
resolved from the directory containing the selected configuration file, so they
do not depend on cron's working directory.

## Configuration

`config.example.json` contains every supported setting:

```json
{
  "log_dir": "./logs",
  "disk_mount": "/",
  "cpu_threshold": 80,
  "mem_threshold": 80,
  "disk_threshold": 90,
  "net_threshold_kbps": 10240,
  "max_log_bytes": 5000000,
  "backup_count": 3,
  "smtp": {
    "enabled": false,
    "host": "smtp.gmail.com",
    "port": 587,
    "security": "starttls",
    "timeout_seconds": 15,
    "sender_email": "your_email@example.com",
    "receiver_email": "your_email@example.com",
    "username": "your_email@example.com",
    "password_env": "SYSMON_EMAIL_PASSWORD",
    "subject_prefix": "[SysMon]"
  }
}
```

Thresholds are triggered only when a metric is greater than the configured
value. CPU, memory, and disk values must be between 0 and 100. Network throughput
uses decimal kilobits per second (1 kbps = 1,000 bits per second).

Set `max_log_bytes` to `0` to disable rotation. `backup_count` controls how many
rotated files are retained.

### Email alerts

Email is off in the example configuration, which makes the first local run safe.
To enable it:

1. Set `smtp.enabled` to `true` and enter the SMTP account details.
2. Choose `starttls` (commonly port 587), `ssl` (commonly port 465), or `none`.
3. Export the password using the variable named by `smtp.password_env`:

   ```bash
   export SYSMON_EMAIL_PASSWORD="your_app_password"
   ```

For Gmail, use an app password rather than the account password. Do not commit a
password, put it directly in `config.json`, or paste it into `run_sysmon.sh`.
For unattended jobs, provide the secret through your service manager's protected
environment configuration.

## Usage

Validate the configuration without collecting metrics:

```bash
./run_sysmon.sh --check-config
```

Run one monitoring cycle:

```bash
./run_sysmon.sh
```

Test collection and threshold behavior without sending email:

```bash
./run_sysmon.sh --no-email
```

Use another configuration file by setting an environment variable:

```bash
SYSMON_CONFIG=/etc/sysmon/config.json ./run_sysmon.sh
```

The launcher uses `.venv/bin/python` when it exists. Set `SYSMON_PYTHON` to use a
different interpreter.

## Scheduling with cron

Find the absolute project path with `pwd`, then add a job with `crontab -e`:

```cron
*/5 * * * * /absolute/path/to/SysMon-main/run_sysmon.sh >> /absolute/path/to/SysMon-main/cron.log 2>&1
```

Cron has a minimal environment. If SMTP is enabled, inject the password through
your host's secure secret-management method. A systemd service with an
`EnvironmentFile` readable only by root is generally safer than storing a secret
in a crontab.

## Log files

- `sysmon.log`: metrics, alerts, and email-delivery status
- `alerts.log`: threshold violations only
- `errors.log`: unexpected runtime failures after configuration has loaded
- `net_state.json`: counters used to calculate throughput between runs

Rotated files use suffixes such as `sysmon.log.1`.

## Tests

Run the standard-library test suite inside the virtual environment:

```bash
./.venv/bin/python -m unittest discover -s tests -v
```

Also check the command paths used by production:

```bash
./run_sysmon.sh --check-config
./run_sysmon.sh --no-email
```

## Troubleshooting

- `config file not found`: copy `config.example.json` to `config.json`.
- `No module named psutil`: install `requirements.txt` in `.venv`.
- SMTP authentication failure: verify the username, app password, port, and
  transport mode. The failure is logged; metric collection still succeeds.
- Invalid disk mount: set `disk_mount` to an existing mounted path on the host.
