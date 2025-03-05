# GHAS API scripts

## Requirements

- Python 3.10 or higher
- Install dependencies with `python3 -mpip install -r requirements.txt`
- Put a GitHub token in your environment in `GITHUB_TOKEN`

## Usage

The date in `--since` can be specified as `YYYY-MM-DD` or as `Nd` where `N` is the number of days ago. Full ISO formats are also supported. If a timezone is not specified, the date is assumed to be in UTC (`Z` timezone).

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

```text
usage: replay_secret_scanning_result_status.py [-h] [--scope {ent,org,repo}] [--state {open,resolved}] [--since SINCE] [--json] [--quote-all] [--hostname HOSTNAME] [--debug] name

Replay secret scanning alert status for a GitHub repository, organization or Enterprise, based on a provided file of previous statuses. This can be useful if a repository is deleted and recreated, and you want to restore
the previous status of the alerts. This script reads a CSV file with a header from stdin, with the following columns: repo, secret, secret_type, state, resolution, resolution_comment, url

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
usage: enrich_code_scanning_alerts.py [-h] [--mitre-cwe-csv MITRE_CWE_CSV] [--metadata-format {codeql,parse_ql}] [--debug] [--format {json,html}] [--fields FIELDS] [--groupby GROUPBY] alerts metadata scope

Add CodeQL metadata to Code Scanning alerts and produce output. This must be the abbreviated version of the JSON output supported by the partner script `list_code_scanning_alerts.py`. The metadata can either be in the format provided by the `codeql resolve metadata` command, or in the format produced by the
script `parse_ql` by the same author as this script.

positional arguments:
  alerts                JSON file containing the alerts to enrich
  metadata              JSON file containing the metadata to add to the alerts, which must be indexed by the rule ID
  scope                 Target of the report - e.g. the org, repo or Enterprise name being scanned

options:
  -h, --help            show this help message and exit
  --mitre-cwe-csv MITRE_CWE_CSV
                        CSV file containing MITRE CWE data for Software Development from https://cwe.mitre.org/data/csv/699.csv.zip
  --metadata-format {codeql,parse_ql}, -m {codeql,parse_ql}
                        Format of the metadata
  --debug, -d           Print debug information
  --format {json,html}, -f {json,html}
                        Output format
  --fields FIELDS, -F FIELDS
                        Comma-separated list of fields to include in the output
  --groupby GROUPBY, -g GROUPBY
                        Field to group the alerts by
```

```text
usage: resolve_duplicate_secret_scanning_alerts.py [-h] [--scope {ent,org,repo}] [--state {open,resolved}] [--since SINCE] [--hostname HOSTNAME] [--debug] [--add-matching-secret OLD_TYPE NEW_TYPE] name

Resolve duplicate secret scanning alerts for a GitHub repository, organization or Enterprise.

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
  --hostname HOSTNAME   GitHub Enterprise hostname (defaults to github.com)
  --debug, -d           Enable debug logging
  --add-matching-secret OLD_TYPE NEW_TYPE, -a OLD_TYPE NEW_TYPE
                        Add a new pair of matched secret types
```

## License

(C) Copyright 2024 GitHub, Inc. This is not open source software, and comes with no support or commitments.
