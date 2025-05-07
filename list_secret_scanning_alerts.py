#!/usr/bin/env python3

"""List secret scanning alerts for a GitHub repository, organization or Enterprise."""

import sys
import argparse
import re
import logging
import datetime
import json
from typing import Generator, Any
from defusedcsv import csv  # type: ignore
from githubapi import GitHub, parse_date


LOG = logging.getLogger(__name__)


def make_result(
    alert: dict, scope: str, name: str, include_secret: bool = True
) -> dict:
    """Make an alert result from the raw data."""
    result = {
        "created_at": alert["created_at"],
        "push_protection_bypassed_by": (
            alert["push_protection_bypassed_by"]["login"]
            if alert["push_protection_bypassed_by"] is not None
            else None
        ),
        "push_protection_bypassed_at": alert["push_protection_bypassed_at"],
        "repo": alert["repository"]["full_name"] if scope != "repo" and "repository" in alert else name,
        "url": alert["html_url"],
        "state": alert["state"],
        "resolution": alert["resolution"],
        "resolved_at": alert["resolved_at"],
        "resolved_by": (
            alert["resolved_by"]["login"] if alert["resolved_by"] is not None else None
        ),
        "resolution_comment": alert["resolution_comment"],
        "validity": alert["validity"],
        "secret_type": alert["secret_type"],
        "multi_repo": alert.get("multi_repo"),
        "publicly_leaked": alert.get("publicly_leaked"),
        "push_protection_bypass_request_reviewer": (
            alert["push_protection_bypass_request_reviewer"]["login"]
            if alert.get("push_protection_bypass_request_reviewer") is not None
            else None
        ),
        "push_protection_bypass_request_reviewer_comment": alert.get(
            "push_protection_bypass_request_reviewer_comment"
        ),
        "push_protection_bypass_request_comment": alert.get(
            "push_protection_bypass_request_comment"
        )
    }

    if include_secret:
        result["secret"] = alert["secret"]

    return result


def to_list(result: dict) -> list[str|None]:
    return [
        result["created_at"],
        result["push_protection_bypassed_by"],
        result["push_protection_bypassed_at"],
        result["repo"],
        result["url"],
        result["state"],
        result["resolution"],
        result["resolved_at"],
        result["resolved_by"],
        result["resolution_comment"],
        result["validity"],
        result["secret_type"],
        (result["secret"] if "secret" in result else None),
    ]


def output_csv(results: list[dict], quote_all: bool) -> None:
    """Write the results to stdout as CSV."""
    writer = csv.writer(
        sys.stdout, quoting=csv.QUOTE_ALL if quote_all else csv.QUOTE_MINIMAL
    )

    writer.writerow(
        [
            "created_at",
            "bypassed_by",
            "bypassed_at",
            "repo",
            "url",
            "state",
            "resolution",
            "resolved_at",
            "resolved_by",
            "resolution_comment",
            "validity",
            "secret_type",
            "secret",
        ]
    )

    for result in results:
        writer.writerow(to_list(result))


def list_secret_scanning_alerts(
    name,
    scope: str,
    hostname: str,
    state: str | None = None,
    since: datetime.datetime | None = None,
    include_secret: bool = False,
    bypassed: bool = False,
    raw: bool = False,
) -> Generator[dict, None, None]:
    g = GitHub(hostname=hostname)
    alerts = g.list_secret_scanning_alerts(
        name, state=state, since=since, scope=scope, bypassed=bypassed
    )
    if raw:
        return alerts
    else:
        results = (
            make_result(alert, scope, name, include_secret=include_secret)
            for alert in alerts
        )
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
        "--bypassed",
        "-b",
        action="store_true",
        help="Only show alerts where push protection was bypassed",
    )
    parser.add_argument(
        "--state",
        "-s",
        type=str,
        choices=["open", "resolved"],
        required=False,
        help="State of the alerts to query",
    )
    parser.add_argument(
        "--no-include-secret",
        "-n",
        action="store_true",
        help="Do not include the secret in the output",
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
        '--raw', '-r', action="store_true", help="Output the raw data from the GitHub API"
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
        "--debug", "-d", action="store_true", help="Enable debug logging"
    )


def main() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description=__doc__)
    add_args(parser)
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)

    since = parse_date(args.since)

    LOG.debug("Since: %s (%s) [%s]", since, args.since, type(since))

    if args.raw:
        args.json = True

    scope = "repo" if ("/" in args.name and args.scope != "repo") else args.scope
    name = args.name
    state = args.state
    hostname = args.hostname
    include_secret = not args.no_include_secret
    bypassed = args.bypassed

    if not GitHub.check_name(name, scope):
        raise ValueError("Invalid name: %s for %s", name, scope)

    results = list_secret_scanning_alerts(
        name,
        scope,
        hostname,
        state=state,
        since=since,
        include_secret=include_secret,
        bypassed=bypassed,
        raw=args.raw,
    )

    if args.json:
        print(json.dumps(list(results), indent=2))
    else:
        output_csv(results, args.quote_all)  # type: ignore


if __name__ == "__main__":
    main()
