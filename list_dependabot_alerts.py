#!/usr/bin/env python3

"""List Dependabot alerts for a GitHub repository, organization or Enterprise."""

import sys
import argparse
import logging
import datetime
import json
from typing import Generator
from defusedcsv import csv  # type: ignore
from githubapi import GitHub, parse_date


LOG = logging.getLogger(__name__)


def make_result(
    alert: dict, scope: str, name: str
) -> dict:
    """Make an alert result from the raw data."""
    result = {
        "created_at": alert["created_at"],
        "repo": alert["repository"]["full_name"] if scope != "repo" and "repository" in alert else name,
        "url": alert["html_url"],
        "state": alert["state"],
        "dismissed_at": alert["dismissed_at"],
        "dismissed_by": alert["dismissed_by"]["login"] if alert["dismissed_by"] else None,
        "dismissed_reason": alert["dismissed_reason"],
        "dismissed_comment": alert["dismissed_comment"],
        "fixed_at": alert["fixed_at"],
        "auto_dismissed_at": alert.get("auto_dismissed_at"),
        "package_name": alert["security_advisory"]["package"]["name"],
        "package_ecosystem": alert["security_advisory"]["package"]["ecosystem"],
        "severity": alert["security_advisory"]["severity"],
        "cve_id": alert["security_advisory"]["cve_id"],
        "ghsa_id": alert["security_advisory"]["ghsa_id"],
        "summary": alert["security_advisory"]["summary"],
        "description": alert["security_advisory"]["description"],
        "vulnerable_version_range": alert["security_vulnerability"]["vulnerable_version_range"],
        "first_patched_version": alert["security_vulnerability"]["first_patched_version"]["identifier"] if alert["security_vulnerability"]["first_patched_version"] else None,
        "manifest_path": alert["dependency"]["manifest_path"] if "dependency" in alert and alert["dependency"] else None,
        "scope": alert["dependency"]["scope"] if "dependency" in alert and alert["dependency"] else None,
    }

    return result


def to_list(result: dict) -> list[str|None]:
    return [
        result["created_at"],
        result["repo"],
        result["url"],
        result["state"],
        result["dismissed_at"],
        result["dismissed_by"],
        result["dismissed_reason"],
        result["dismissed_comment"],
        result["fixed_at"],
        result["auto_dismissed_at"],
        result["package_name"],
        result["package_ecosystem"],
        result["severity"],
        result["cve_id"],
        result["ghsa_id"],
        result["summary"],
        result["description"],
        result["vulnerable_version_range"],
        result["first_patched_version"],
        result["manifest_path"],
        result["scope"],
    ]


def output_csv(results: list[dict], quote_all: bool) -> None:
    """Write the results to stdout as CSV."""
    writer = csv.writer(
        sys.stdout, quoting=csv.QUOTE_ALL if quote_all else csv.QUOTE_MINIMAL
    )

    writer.writerow(
        [
            "created_at",
            "repo",
            "url",
            "state",
            "dismissed_at",
            "dismissed_by",
            "dismissed_reason",
            "dismissed_comment",
            "fixed_at",
            "auto_dismissed_at",
            "package_name",
            "package_ecosystem",
            "severity",
            "cve_id",
            "ghsa_id",
            "summary",
            "description",
            "vulnerable_version_range",
            "first_patched_version",
            "manifest_path",
            "scope",
        ]
    )

    for result in results:
        writer.writerow(to_list(result))


def list_dependabot_alerts(name: str, scope: str, hostname: str, state: str|None=None, since: datetime.datetime|None=None, raw: bool=False, verify: bool | str = True, progress: bool = True) -> Generator[dict, None, None]:
    g = GitHub(hostname=hostname, verify=verify)
    alerts = g.list_dependabot_alerts(name, state=state, since=since, scope=scope, progress=progress)
    if raw:
        return alerts
    else:
        results = (make_result(alert, scope, name) for alert in alerts)
        return results


def add_args(parser: argparse.ArgumentParser) -> None:
    """Add command-line arguments to the parser."""
    parser.add_argument(
        "name", type=str, help="Name of the repo/org/Enterprise to query"
    )
    parser.add_argument(
        "--scope",
        type=str,
        default="org",
        choices=["ent", "org", "repo"],
        required=False,
        help="Scope of the query",
    )
    parser.add_argument(
        "--state",
        "-s",
        type=str,
        choices=["auto_dismissed", "dismissed", "fixed", "open"],
        required=False,
        help="State of the alerts to query",
    )
    parser.add_argument(
        "--since",
        "-S",
        type=str,
        required=False,
        help="Only show alerts created after this date/time - ISO 8601 format, e.g. 2024-10-08 or 2024-10-08T12:00; or Nd format, e.g. 7d for 7 days ago",
    )
    parser.add_argument(
        "--json", action="store_true", help="Output in JSON format (otherwise CSV)"
    )
    parser.add_argument(
        "--raw", "-r", action="store_true", help="Output raw JSON data from the API"
    )
    parser.add_argument(
        "--quote-all", "-q", action="store_true", help="Quote all fields in CSV output"
    )
    parser.add_argument(
        "--hostname",
        type=str,
        default="github.com",
        required=False,
        help="GitHub Enterprise hostname (defaults to github.com)",
    )
    parser.add_argument(
        "--ca-cert-bundle",
        "-C",
        type=str,
        required=False,
        help="Path to CA certificate bundle in PEM format (e.g. for self-signed server certificates)"
    )
    parser.add_argument(
        "--no-verify-tls",
        action="store_true",
        help="Do not verify TLS connection certificates (warning: insecure)"
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-error log messages",
    )
    parser.add_argument(
        "--debug", "-d", action="store_true", help="Enable debug logging"
    )


def main() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description=__doc__)
    add_args(parser)
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO if not args.quiet else logging.ERROR, format="%(asctime)s %(levelname)s %(message)s")

    since = parse_date(args.since)

    LOG.debug("Since: %s (%s) [%s]", since, args.since, type(since))

    if args.raw:
        args.json = True

    scope = "repo" if ("/" in args.name and args.scope != "repo") else args.scope
    name = args.name
    state = args.state
    hostname = args.hostname
    verify = True

    if args.ca_cert_bundle:
        verify = args.ca_cert_bundle

    if args.no_verify_tls:
        verify = False
        LOG.warning("Disabling TLS verification. This is insecure and should not be used in production")
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if not GitHub.check_name(name, scope):
        raise ValueError("Invalid name: %s for %s", name, scope)

    results = list_dependabot_alerts(name, scope, hostname, state=state, since=since, raw=args.raw, verify=verify, progress=not args.quiet)

    if args.json:
        print(json.dumps(list(results), indent=2))
    else:
        output_csv(results, args.quote_all) # type: ignore


if __name__ == "__main__":
    main()
