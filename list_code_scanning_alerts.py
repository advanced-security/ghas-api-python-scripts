#!/usr/bin/env python3

"""List code scanning alerts for a GitHub repository, organization or Enterprise."""

import sys
import argparse
import re
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
    cwes = [tag for tag in alert["rule"]["tags"] if tag.startswith("external/cwe/cwe-")]
    if len(cwes) > 0:
        cwe = int(cwes[0].split("/")[2].split("-")[1])
    else:
        cwe = 0

    result = {
        "created_at": alert["created_at"],
        "repo": alert["repository"]["full_name"] if scope != "repo" else name,
        "url": alert["html_url"],
        "state": alert["state"],
        "fixed_at": alert["fixed_at"],
        "dismissed_reason": alert["dismissed_reason"],
        "dismissed_at": alert["dismissed_at"],
        "dismissed_by": alert["dismissed_by"]["login"] if alert["dismissed_by"] else None,
        "dismissed_comment": alert["dismissed_comment"],
        "rule_id": alert["rule"]["id"],
        "rule_severity": alert["rule"]["severity"],
        "rule_description": alert["rule"]["description"],
        "rule_full_description": alert["rule"]["full_description"],
        "rule_security_severity_level": alert["rule"]["security_severity_level"] if "security_severity_level" in alert["rule"] else None,
        "cwe": cwe,
        "rule_help": alert["rule"]["help"],
        "tool_name": alert["tool"]["name"],
        "commit_sha": alert["most_recent_instance"]["commit_sha"],
        "message": alert["most_recent_instance"]["message"]["text"],
        "ref": alert["most_recent_instance"]["ref"],
        "path": alert["most_recent_instance"]["location"]["path"],
        "start_line": alert["most_recent_instance"]["location"]["start_line"],
        "start_column": alert["most_recent_instance"]["location"]["start_column"],
        "end_line": alert["most_recent_instance"]["location"]["end_line"],
        "end_column": alert["most_recent_instance"]["location"]["end_column"],
    }

    return result


def to_list(result: dict) -> list[str|int]:
    return [
        result["created_at"],
        result["repo"],
        result["url"],
        result["state"],
        result["fixed_at"],
        result["dismissed_reason"],
        result["dismissed_at"],
        result["dismissed_by"],
        result["dismissed_comment"],
        result["rule_id"],
        result["rule_severity"],
        result["cwe"],
        result["rule_description"],
        result["rule_full_description"],
        result["rule_security_severity_level"],
        result["rule_help"],
        result["tool_name"],
        result["commit_sha"],
        result["ref"],
        result["path"],
        int(result["start_line"]),
        int(result["start_column"]),
        int(result["end_line"]),
        int(result["end_column"]),
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
            "fixed_at",
            "dismissed_reason",
            "dismissed_at",
            "dismissed_by",
            "dismissed_comment",
            "rule_id",
            "rule_severity",
            "rule_description",
            "rule_full_description",
            "rule_security_severity_level",
            "cwe",
            "rule_help",
            "tool_name",
            "commit_sha",
            "ref",
            "path",
            "start_line",
            "start_column",
            "end_line",
            "end_column",
        ]
    )

    for result in results:
        writer.writerow(to_list(result))


def list_code_scanning_alerts(name: str, scope: str, hostname: str, state: str|None=None, since: datetime.datetime|None=None, raw: bool=False) -> Generator[dict, None, None]:
    g = GitHub(hostname=hostname)
    alerts = g.list_code_scanning_alerts(name, state=state, since=since, scope=scope)
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
        choices=["open", "resolved"],
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

    if not GitHub.check_name(name, scope):
        raise ValueError("Invalid name: %s for %s", name, scope)

    results = list_code_scanning_alerts(name, scope, hostname, state=state, since=since, raw=args.raw)

    if args.json:
        print(json.dumps(list(results), indent=2))
    else:
        output_csv(results, args.quote_all) # type: ignore


if __name__ == "__main__":
    main()
