# GitHub Advanced Security (GHAS) API scripts

GitHub Advanced Security offers a range of rich REST APIs to access and manage alerts.

This is a set of scripts that use these APIs to access and manage alerts. The scripts are written in Python and use a wrapper around the API requests to manage authentication, pagination and rate limiting.

> [!NOTE]
> This is an unofficial tool created by Field Security Specialists, and is not officially supported by GitHub.

## 📦 Requirements

- Python 3.10 or higher
- Install dependencies with `python3 -mpip install -r requirements.txt --user`
  - Consider using a virtualenv, managed by `pyenv`
  - On MacOS, add `--break-system-packages` to the end of the install command, if you are not using a virtualenv: `python3 -mpip install -r requirements.txt --user --break-system-packages`
  - to use PDF output in `enrich_code_scanning_alerts.py`, also install `playwright` with `python3 -mpip install playwright --user` and run `playwright install` to install the required browsers
- Put a suitable GitHub access token in your environment in `GITHUB_TOKEN`
  - for example with `GITHUB_TOKEN=$(gh auth token)` before the command
  - requires read access to GitHub Advanced Security alerts
  - requires read access to the repository, organization or Enterprise you are querying
  - Note that Secret Scanning alerts are only available to admins of the repository, organization or Enterprise, a security manager, or where otherwise granted access

## 🚀 Scripts usage

A note on common arguments: generally, the date in `--since` can be specified as `YYYY-MM-DD` or as `Nd` where `N` is the number of days ago. Full ISO formats are also supported. If a timezone is not specified, the date is assumed to be in UTC (`Z` timezone).

### List secret scanning alerts

This script retrieves secret scanning alerts from GitHub repositories, organizations, or Enterprises and outputs them in CSV or JSON format. It supports filtering by state, date, and push protection bypass status. Use this to audit, analyze, or export secret scanning data for compliance or security purposes.

```text
usage: list_secret_scanning_alerts.py [-h] [--scope {ent,org,repo}] [--generic] [--bypassed] [--state {open,resolved}]
                                      [--no-include-secret] [--include-locations] [--include-commit] [--since SINCE]
                                      [--json] [--raw] [--quote-all] [--hostname HOSTNAME]
                                      [--ca-cert-bundle CA_CERT_BUNDLE] [--no-verify-tls] [--quiet] [--debug]
                                      name

List secret scanning alerts for a GitHub repository, organization or Enterprise.

positional arguments:
  name                  Name of the repo/org/Enterprise to query

options:
  -h, --help            show this help message and exit
  --scope {ent,org,repo}
                        Scope of the query
  --generic, -g         Include generic secret types (not just vendor secret types/custom patterns, which is the
                        default)
  --bypassed, -b        Only show alerts where push protection was bypassed
  --state {open,resolved}, -s {open,resolved}
                        State of the alerts to query
  --no-include-secret, -n
                        Do not include the secret in the output
  --include-locations, -l
                        Include locations in the output
  --include-commit, -c  Include commit date and committer in the output
  --since SINCE, -S SINCE
                        Only show alerts created after this date/time - ISO 8601 format, e.g. 2024-10-08 or
                        2024-10-08T12:00; or Nd format, e.g. 7d for 7 days ago
  --json                Output in JSON format (otherwise CSV)
  --raw, -r             Output the raw data from the GitHub API
  --quote-all, -Q       Quote all fields in CSV output
  --hostname HOSTNAME   GitHub Enterprise hostname (defaults to github.com)
  --ca-cert-bundle CA_CERT_BUNDLE, -C CA_CERT_BUNDLE
                        Path to CA certificate bundle in PEM format (e.g. for self-signed server certificates)
  --no-verify-tls       Do not verify TLS connection certificates (warning: insecure)
  --quiet, -q           Suppress non-error log messages
  --debug, -d           Enable debug logging
```

### List code scanning alerts

This script retrieves code scanning alerts from GitHub repositories, organizations, or Enterprises and outputs them in CSV or JSON format. It supports filtering by state and date. Use this to audit, track, or export code scanning findings for reporting and analysis.

```text
usage: list_code_scanning_alerts.py [-h] [--scope {ent,org,repo}] [--state {open,resolved}] [--since SINCE] [--json]
                                    [--raw] [--quote-all] [--hostname HOSTNAME] [--ca-cert-bundle CA_CERT_BUNDLE]
                                    [--no-verify-tls] [--debug]
                                    name

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
                        Only show alerts created after this date/time - ISO 8601 format, e.g. 2024-10-08 or
                        2024-10-08T12:00; or Nd format, e.g. 7d for 7 days ago
  --json                Output in JSON format (otherwise CSV)
  --raw, -r             Output raw JSON data from the API
  --quote-all, -q       Quote all fields in CSV output
  --hostname HOSTNAME   GitHub Enterprise hostname (defaults to github.com)
  --ca-cert-bundle CA_CERT_BUNDLE, -C CA_CERT_BUNDLE
                        Path to CA certificate bundle in PEM format (e.g. for self-signed server certificates)
  --no-verify-tls       Do not verify TLS connection certificates (warning: insecure)
  --debug, -d           Enable debug logging
```

### List Dependabot alerts

This script retrieves Dependabot alerts from GitHub repositories, organizations, or Enterprises and outputs them in CSV or JSON format. It supports filtering by state and date. Use this to audit, track, or export Dependabot security vulnerability findings for dependency management and reporting.

```text
usage: list_dependabot_alerts.py [-h] [--scope {ent,org,repo}] [--state {auto_dismissed,dismissed,fixed,open}]
                                 [--since SINCE] [--json] [--raw] [--quote-all] [--hostname HOSTNAME]
                                 [--ca-cert-bundle CA_CERT_BUNDLE] [--no-verify-tls] [--quiet] [--debug]
                                 name

List Dependabot alerts for a GitHub repository, organization or Enterprise.

positional arguments:
  name                  Name of the repo/org/Enterprise to query

options:
  -h, --help            show this help message and exit
  --scope {ent,org,repo}
                        Scope of the query
  --state {auto_dismissed,dismissed,fixed,open}, -s {auto_dismissed,dismissed,fixed,open}
                        State of the alerts to query
  --since SINCE, -S SINCE
                        Only show alerts created after this date/time - ISO 8601 format, e.g. 2024-10-08 or
                        2024-10-08T12:00; or Nd format, e.g. 7d for 7 days ago
  --json                Output in JSON format (otherwise CSV)
  --raw, -r             Output raw JSON data from the API
  --quote-all, -q       Quote all fields in CSV output
  --hostname HOSTNAME   GitHub Enterprise hostname (defaults to github.com)
  --ca-cert-bundle CA_CERT_BUNDLE, -C CA_CERT_BUNDLE
                        Path to CA certificate bundle in PEM format (e.g. for self-signed server certificates)
  --no-verify-tls       Do not verify TLS connection certificates (warning: insecure)
  --quiet               Suppress non-error log messages
  --debug, -d           Enable debug logging
```

### Replay code scanning alert status

This script replays or restores the status of code scanning alerts based on a previously exported CSV file. It's useful when alerts need to be re-dismissed after a repository is recreated or when migrating alert states between environments. The script reads from stdin and matches alerts by location.

```text
usage: replay_code_scanning_alert_status.py [-h] [--scope {ent,org,repo}] [--state {open,resolved}] [--since SINCE]
                                            [--json] [--quote-all] [--hostname HOSTNAME]
                                            [--ca-cert-bundle CA_CERT_BUNDLE] [--no-verify-tls] [--debug]
                                            name

Replay code scanning alert status for a GitHub repository, organization or Enterprise, based on a provide file of
previous statuses.

positional arguments:
  name                  Name of the repo/org/Enterprise to query

options:
  -h, --help            show this help message and exit
  --scope {ent,org,repo}
                        Scope of the query
  --state {open,resolved}, -s {open,resolved}
                        State of the alerts to query
  --since SINCE, -S SINCE
                        Only show alerts created after this date/time - ISO 8601 format, e.g. 2024-10-08 or
                        2024-10-08T12:00; or Nd format, e.g. 7d for 7 days ago
  --json                Output in JSON format (otherwise CSV)
  --quote-all, -q       Quote all fields in CSV output
  --hostname HOSTNAME   GitHub Enterprise hostname (defaults to github.com)
  --ca-cert-bundle CA_CERT_BUNDLE, -C CA_CERT_BUNDLE
                        Path to CA certificate bundle in PEM format (e.g. for self-signed server certificates)
  --no-verify-tls       Do not verify TLS connection certificates (warning: insecure)
  --debug, -d           Enable debug logging
```

### Replay secret scanning alert status

This script replays or restores the status of secret scanning alerts based on a previously exported CSV file. It's particularly useful when a repository is deleted and recreated, allowing you to restore the previous resolution states of alerts. The script reads a CSV file from stdin with columns: repo, secret, secret_type, state, resolution, resolution_comment, url.

```text
usage: replay_secret_scanning_result_status.py [-h] [--scope {ent,org,repo}] [--state {open,resolved}] [--since SINCE]
                                               [--json] [--quote-all] [--hostname HOSTNAME]
                                               [--ca-cert-bundle CA_CERT_BUNDLE] [--no-verify-tls] [--debug]
                                               name

Replay secret scanning alert status for a GitHub repository, organization or Enterprise, based on a provided file of
previous statuses. This can be useful if a repository is deleted and recreated, and you want to restore the previous
status of the alerts. This script reads a CSV file with a header from stdin, with the following columns: repo, secret,
secret_type, state, resolution, resolution_comment, url

positional arguments:
  name                  Name of the repo/org/Enterprise to query

options:
  -h, --help            show this help message and exit
  --scope {ent,org,repo}
                        Scope of the query
  --state {open,resolved}, -s {open,resolved}
                        State of the alerts to query
  --since SINCE, -S SINCE
                        Only show alerts created after this date/time - ISO 8601 format, e.g. 2024-10-08 or
                        2024-10-08T12:00; or Nd format, e.g. 7d for 7 days ago
  --json                Output in JSON format (otherwise CSV)
  --quote-all, -q       Quote all fields in CSV output
  --hostname HOSTNAME   GitHub Enterprise hostname (defaults to github.com)
  --ca-cert-bundle CA_CERT_BUNDLE, -C CA_CERT_BUNDLE
                        Path to CA certificate bundle in PEM format (e.g. for self-signed server certificates)
  --no-verify-tls       Do not verify TLS connection certificates (warning: insecure)
  --debug, -d           Enable debug logging
```

### Enrich code scanning alerts

This script enriches code scanning alerts with additional CodeQL metadata, including query descriptions, MITRE CWE information, and other contextual details. It produces enhanced output in JSON, HTML, or PDF format, making it easier to generate comprehensive security reports. The alerts input must be in JSON format from `list_code_scanning_alerts.py`.

Using the PDF mode needs you to install `playwright`, which isn't in the general `requirements.txt`.

You can use `python3 -mpip install playwright` to get it, then run `playwright install` to install the required browsers.

```text
usage: enrich_code_scanning_alerts.py [-h] [--mitre-cwe-csv MITRE_CWE_CSV] [--metadata-format {codeql,parse_ql}]
                                      [--debug] [--format {json,html,pdf}] [--fields FIELDS] [--groupby GROUPBY]
                                      alerts metadata scope

Add CodeQL metadata to Code Scanning alerts and produce output. This must be the abbreviated version of the JSON
output supported by the partner script `list_code_scanning_alerts.py`. The metadata can either be in the format
provided by the `codeql resolve metadata` command, or in the format produced by the script `parse_ql` by the same
author as this script.

positional arguments:
  alerts                JSON file containing the alerts to enrich
  metadata              JSON file containing the metadata to add to the alerts, which must be indexed by the rule ID
  scope                 Target of the report - e.g. the org, repo or Enterprise name being scanned

options:
  -h, --help            show this help message and exit
  --mitre-cwe-csv MITRE_CWE_CSV
                        CSV file containing MITRE CWE data for Software Development from
                        https://cwe.mitre.org/data/csv/699.csv.zip
  --metadata-format {codeql,parse_ql}, -m {codeql,parse_ql}
                        Format of the metadata
  --debug, -d           Print debug information
  --format {json,html,pdf}, -f {json,html,pdf}
                        Output format
  --fields FIELDS, -F FIELDS
                        Comma-separated list of fields to include in the output
  --groupby GROUPBY, -g GROUPBY
                        Field to group the alerts by
```

### Resolve duplicate secret scanning alerts

This script identifies and resolves duplicate secret scanning alerts that occur when the same secret is detected by multiple patterns. For example, when a Google Cloud private key ID is detected both as a standalone secret and as part of service account credentials, this script can automatically resolve the duplicate. Use the `--add-matching-secret` option to add custom pairs of matching secret types.

```text
usage: resolve_duplicate_secret_scanning_alerts.py [-h] [--scope {ent,org,repo}] [--state {open,resolved}]
                                                   [--since SINCE] [--hostname HOSTNAME]
                                                   [--ca-cert-bundle CA_CERT_BUNDLE] [--no-verify-tls] [--debug]
                                                   [--add-matching-secret OLD_TYPE NEW_TYPE]
                                                   name

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
                        Only show alerts created after this date/time - ISO 8601 format, e.g. 2024-10-08 or
                        2024-10-08T12:00; or Nd format, e.g. 7d for 7 days ago
  --hostname HOSTNAME   GitHub Enterprise hostname (defaults to github.com)
  --ca-cert-bundle CA_CERT_BUNDLE, -C CA_CERT_BUNDLE
                        Path to CA certificate bundle in PEM format (e.g. for self-signed server certificates)
  --no-verify-tls       Do not verify TLS connection certificates (warning: insecure)
  --debug, -d           Enable debug logging
  --add-matching-secret OLD_TYPE NEW_TYPE, -a OLD_TYPE NEW_TYPE
                        Add a new pair of matched secret types
```

### Close code scanning alerts

This script bulk-closes all open code scanning alerts for a specified repository. It's useful for cleanup operations, such as dismissing false positives or marking alerts as "won't fix" across an entire repository. The script supports dry-run mode to preview changes before applying them.

```text
usage: close_code_scanning_alerts.py [-h] [--resolution {false positive,won't fix,used in tests}] [--dry-run]
                                     [--hostname HOSTNAME] [--ca-cert-bundle CA_CERT_BUNDLE] [--no-verify-tls] [-d]
                                     repo_name

Close all open code scanning alerts for a repository.

positional arguments:
  repo_name             The owner/repo of the repository to close alerts for.

options:
  -h, --help            show this help message and exit
  --resolution {false positive,won't fix,used in tests}
                        The resolution of the alert.
  --dry-run             Print the alerts that would be closed, but don't actually close them.
  --hostname HOSTNAME   GitHub Enterprise hostname (defaults to github.com)
  --ca-cert-bundle CA_CERT_BUNDLE, -C CA_CERT_BUNDLE
                        Path to CA certificate bundle in PEM format (e.g. for self-signed server certificates)
  --no-verify-tls       Do not verify TLS connection certificates (warning: insecure)
  -d, --debug           Print debug messages to the console.
```

### Estimate push protection rate

This script estimates what percentage of previously detected secrets would have been caught by push protection if it had been enabled. It compares a list of historical secret detections against the current patterns that have push protection enabled, helping you understand the potential impact of enabling this feature.

```text
usage: estimate_push_protection_rate.py [-h] [--cut-off-date CUT_OFF_DATE] secrets_file patterns_file

Estimate push protection rate for secrets

positional arguments:
  secrets_file          Path to the file containing the list of secrets
  patterns_file         Path to the file containing the list of patterns with push protection

options:
  -h, --help            show this help message and exit
  --cut-off-date CUT_OFF_DATE
                        ISO date string to filter secrets detected after this date (e.g., 2023-01-01)
```

## 🔧 The `githubapi.py` Module

The `githubapi.py` module is a lightweight GitHub API client that provides a wrapper around the GitHub REST API. It handles authentication, pagination, rate limiting, and provides convenient methods for accessing GitHub Advanced Security alerts. All scripts in this repository use this module as their foundation.

### Key Features

- **Authentication**: Automatically handles GitHub token authentication via the `GITHUB_TOKEN` environment variable or passed token
- **Automatic Pagination**: Supports cursor-based pagination to retrieve all results across multiple pages
- **Rate Limiting**: Automatically detects and handles GitHub API rate limits by waiting and retrying
- **Flexible Scoping**: Query at repository, organization, or Enterprise level
- **Date Filtering**: Filter results by date with support for ISO 8601 formats or relative dates (e.g., `7d` for 7 days ago)
- **TLS Support**: Configurable TLS certificate verification, including support for custom CA bundles and self-signed certificates
- **Error Handling**: Robust error handling with detailed logging

### The `GitHub` Class

The main class in the module is `GitHub`, which provides methods to interact with the GitHub API.

#### Initialization

```python
from githubapi import GitHub

# Initialize with token from environment variable
gh = GitHub()

# Or provide token explicitly
gh = GitHub(token=some_variable)

# For GitHub Enterprise Server with custom hostname
gh = GitHub(hostname="github.example.com")

# With custom CA certificate bundle
gh = GitHub(verify="/path/to/ca-bundle.pem")

# Disable TLS verification (not recommended)
gh = GitHub(verify=False)
```

#### Main Methods

**`query(scope, name, endpoint, query=None, data=None, method="GET", since=None, date_field="created_at", paging="cursor", progress=True)`**

The core method for querying the GitHub API with automatic pagination and rate limiting.

- `scope`: One of `"repo"`, `"org"`, or `"ent"` (Enterprise)
- `name`: Repository name (format: `owner/repo`), organization name, or Enterprise slug
- `endpoint`: API endpoint path (e.g., `/secret-scanning/alerts`)
- `query`: Optional dictionary of query parameters
- `since`: Optional datetime to filter results by creation date
- `date_field`: Field name used for date filtering (default: `"created_at"`)
- `paging`: Pagination mode - `"cursor"`, `"page"`, or `None` for no pagination
- `progress`: Whether to show a progress bar (default: `True`)

**`query_once(scope, name, endpoint, query=None, data=None, method="GET")`**

Make a single API request without pagination.

**`_get(url, headers=None, params=None)`**

Make a GET request to the specified URL with optional headers and parameters, respecting rate limits automatically by raising a `RateLimited` exception when necessary.

**`_do(url, headers=None, params=None, data=None, method="GET")`**

Make an HTTP request with the specified method, handling rate limits and errors.

**`list_code_scanning_alerts(name, state=None, since=None, scope="org", progress=True)`**

List code scanning alerts with optional state and date filtering.

**`list_secret_scanning_alerts(name, state=None, since=None, scope="org", bypassed=False, generic=False, progress=True)`**

List secret scanning alerts with optional filtering by state, date, bypass status, and secret type.

**`list_dependabot_alerts(name, state=None, since=None, scope="org", progress=True)`**

List Dependabot alerts with optional state and date filtering.

### Utility Functions

**`parse_date(date_string)`**

Parse a date string into a datetime object. Supports:

- Relative dates: `"7d"` (7 days ago), `"30d"` (30 days ago)
- ISO 8601 dates: `"2024-10-08"`, `"2024-10-08T12:00:00Z"`
- Partial ISO dates (timezone automatically added if missing)

```python
from githubapi import parse_date

# Relative date
since = parse_date("7d")  # 7 days ago

# Absolute date
since = parse_date("2024-10-08")  # Specific date
```

### Usage Example

Here's a complete example showing how to use `githubapi.py` in your own scripts:

```python
#!/usr/bin/env python3

import os
from githubapi import GitHub, parse_date

# Initialize the GitHub client
gh = GitHub(token=os.getenv("GITHUB_TOKEN"))

# List secret scanning alerts for an organization from the last 30 days
since = parse_date("30d")
for alert in gh.list_secret_scanning_alerts(
    name="my-org",
    scope="org",
    state="open",
    since=since
):
    print(f"Alert: {alert['secret_type']} in {alert['repository']['full_name']}")

# Query a custom endpoint with pagination
for result in gh.query(
    scope="org",
    name="my-org",
    endpoint="/repos",
    paging="cursor"
):
    print(f"Repository: {result['name']}")
```

### Error Handling and Rate Limiting

The module automatically handles:

- **Rate Limits**: When approaching the API rate limit, the client automatically slows down requests and waits when the limit is reached
- **Connection Errors**: Gracefully handles network issues and stops with available data
- **HTTP Errors**: Raises appropriate exceptions for 4xx and 5xx status codes

All operations include debug logging that can be enabled with `logging.basicConfig(level=logging.DEBUG)`.

## 🛠️ Alternative tools

There are several alternative tools and scripts available for managing GitHub Advanced Security alerts. Some popular options include:

- [GHAS to CSV](https://github.com/advanced-security/ghas-to-csv): A tool for exporting GitHub Advanced Security alerts to CSV format.
- [GHASToolkit for Python](https://github.com/GeekMasher/ghastoolkit): A collection of tools for working with GitHub Advanced Security, including alert management.
- [GitHub CLI](https://cli.github.com/): A command-line tool for interacting with GitHub, including managing security alerts.
- [GitHub REST API](https://docs.github.com/en/rest): Directly use the GitHub REST API to create custom scripts for managing alerts.

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to this project.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details

## 🆘 Support

> [!NOTE]
> This is an _unofficial_ tool created by Field Security Specialists, and is not officially supported by GitHub.

See [SUPPORT.md](SUPPORT.md) for support options.

## 📜 Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for our Code of Conduct.

## 🛡️ Privacy

See [PRIVACY.md](PRIVACY.md) for the privacy notice.
