#!/usr/bin/env python3

"""Replay secret scanning alert status for a GitHub repository, organization or Enterprise, based on a provided file of previous statuses.

This can be useful if a repository is deleted and recreated, and you want to restore the previous status of the alerts.

This script reads a CSV file with a header from stdin, with the following columns: repo, secret, secret_type, state, resolution, resolution_comment, url
"""

import sys
import argparse
import re
import logging
import datetime
import json
from typing import Generator
from collections import defaultdict
from defusedcsv import csv  # type: ignore
from githubapi import GitHub, parse_date
from list_secret_scanning_alerts import list_secret_scanning_alerts


LOG = logging.getLogger(__name__)


def existing_results_by_secret(reader: csv.DictReader) -> dict:
    """Index results by secret and type for easy lookup."""

    existing_results: dict = {}

    for result in reader:
        repo = result["repo"]
        secret_type = result["secret_type"]
        secret = result["secret"]

        existing_results[repo] = (
            {} if repo not in existing_results else existing_results[repo]
        )
        existing_results[repo][secret] = (
            {} if secret not in existing_results[repo] else existing_results[repo][secret]
        )
        existing_results[repo][secret][secret_type] = result

    return existing_results


def change_state(hostname, result: dict, res: dict) -> None:
    """Change the state of the alert to match the existing result using the GitHub API to update the alert."""
    g = GitHub(hostname=hostname)

    repo_name = result["repo"]

    state_update = {
        "state": res["state"],
        "resolution": res["resolution"],
        "resolution_comment": res["resolution_comment"],
    }

    alert_number = result["url"].split("/")[-1]

    LOG.debug(f"Changing state of alert {repo_name}/{alert_number} to {state_update}")

    g.query_once(
        "repo",
        repo_name,
        f"/secret-scanning/alerts/{alert_number}",
        data=state_update,
        method="PATCH",
    )

    return


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

    scope = "repo" if "/" in args.name and args.scope != "repo" else args.scope
    name = args.name
    state = args.state
    hostname = args.hostname

    if not GitHub.check_name(args.name, scope):
        raise ValueError("Invalid name: %s for %s", args.name, scope)

    reader = csv.DictReader(sys.stdin)

    if args.debug:
        reader = csv.DictReader(sys.stdin)

    existing_results = existing_results_by_secret(reader)

    LOG.debug(existing_results)

    results = list_secret_scanning_alerts(name, scope, hostname, state=state, since=since)

    for result in results:
        repo = result["repo"]
        secret = result["secret"]
        secret_type = result["secret_type"]

        LOG.debug(f"{repo}, {secret}, {secret_type}")

        try:
            res = existing_results[repo][secret][secret_type]
            LOG.warning(f"Found existing alert: {res}")
        except KeyError:
            continue

        if res["state"] != result["state"]:
            LOG.warning(f"State mismatch: {res['state']} != {result['state']}")

            if result["state"] != "pattern_edited":
                change_state(hostname, result, res)


if __name__ == "__main__":
    main()
