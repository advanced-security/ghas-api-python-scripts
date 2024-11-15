# GHAS API scripts

## Requirements

- Python 3.9 or higher
- Install dependencies with `python3 -mpip install -r requirements.txt`
- Put a GitHub token in your environment in `GITHUB_TOKEN`

## Usage

```text
usage: list_secret_scanning_alerts.py [-h] [--scope {ent,org,repo}] [--bypassed] [--state {open,resolved}] [--no-include-secret] [--since SINCE] [--json] [--quote-all] [--hostname HOSTNAME] [--debug] name

List secret scanning alerts for a GitHub repository, organization or Enterprise.

positional arguments:
  name                  Name of the repo/org/Enterprise to query

options:
  -h, --help            show this help message and exit
  --scope {ent,org,repo}
                        Scope of the query
  --bypassed, -b        Only show alerts where push protection was bypassed
  --state {open,resolved}, -s {open,resolved}
                        State of the alerts to query
  --no-include-secret, -n
                        Do not include the secret in the output
  --since SINCE, -S SINCE
                        Only show alerts created after this date/time - ISO 8601 format, e.g. 2024-10-08 or 2024-10-08T12:00; or Nd format, e.g. 7d for 7 days ago
  --json                Output in JSON format (otherwise CSV)
  --quote-all, -q       Quote all fields in CSV output
  --hostname HOSTNAME   GitHub Enterprise hostname (defaults to github.com)
  --debug, -d           Enable debug logging
```

```text
usage: list_code_scanning_alerts.py [-h] [--scope {ent,org,repo}] [--state {open,resolved}] [--since SINCE] [--json] [--quote-all] [--hostname HOSTNAME] [--debug] name

List code scanning alerts for a GitHub repository, organization or Enterprise.

positional arguments:
  name                  Name of the repo/org/Enterprise to query

options:
  -h, --help            show this help message and exit
  --scope {ent,org,repo}
                        Scope of the query
  --state {open,resolved}, -s {open,resolved}
                        State of the alerts to query
  --since SINCE, -S SINCE
                        Only show alerts created after this date/time - ISO 8601 format, e.g. 2024-10-08 or 2024-10-08T12:00; or Nd format, e.g. 7d for 7 days ago
  --json                Output in JSON format (otherwise CSV)
  --quote-all, -q       Quote all fields in CSV output
  --hostname HOSTNAME   GitHub Enterprise hostname (defaults to github.com)
  --debug, -d           Enable debug logging
```

```text
usage: replay_code_scanning_alert_status.py [-h] [--scope {ent,org,repo}] [--state {open,resolved}] [--since SINCE] [--json] [--quote-all] [--hostname HOSTNAME] [--debug] name

Replay code scanning alert status for a GitHub repository, organization or Enterprise, based on a provide file of previous statuses.

positional arguments:
  name                  Name of the repo/org/Enterprise to query

options:
  -h, --help            show this help message and exit
  --scope {ent,org,repo}
                        Scope of the query
  --state {open,resolved}, -s {open,resolved}
                        State of the alerts to query
  --since SINCE, -S SINCE
                        Only show alerts created after this date/time - ISO 8601 format, e.g. 2024-10-08 or 2024-10-08T12:00; or Nd format, e.g. 7d for 7 days ago
  --json                Output in JSON format (otherwise CSV)
  --quote-all, -q       Quote all fields in CSV output
  --hostname HOSTNAME   GitHub Enterprise hostname (defaults to github.com)
  --debug, -d           Enable debug logging
```

The date in `--since` can be specified as `YYYY-MM-DD` or as `Nd` where `N` is the number of days ago. Full ISO formats are also supported. If a timezone is not specified, the date is assumed to be in UTC (`Z` timezone).

## License

(C) Copyright 2024 GitHub, Inc. This is not open source software, and comes with no support or commitments.
