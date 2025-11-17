#!/usr/bin/env python3

"""Resolve duplicate secret scanning alerts for a GitHub repository, organization or Enterprise."""

import sys
import argparse
import re
import logging
import datetime
import json
from typing import Generator, List, Tuple, Iterable
from collections import defaultdict
from defusedcsv import csv  # type: ignore
from githubapi import GitHub, parse_date
from list_secret_scanning_alerts import list_secret_scanning_alerts


LOG = logging.getLogger(__name__)

# Hardcoded list of matching secrets
MATCHING_SECRETS = [
    ("google_cloud_private_key_id", "google_cloud_service_account_credentials"),
]

def index_results_by_secret(results: Iterable[dict]) -> dict:
    """Index results by secret and type for easy lookup."""

    indexed_results: dict = {}

    for result in results:
        try:
            repo = result["repo"]
            secret_type = result["secret_type"]
            secret = result["secret"]
        except KeyError as e:
            LOG.error(f"Missing key in result: {e}: {result}")
            continue

        # parse out just the private_key_id for matching on google_cloud_service_account_credentials
        if secret_type == "google_cloud_service_account_credentials":
            secret = json.loads(secret)["private_key_id"]

        indexed_results[repo] = (
            {} if repo not in indexed_results else indexed_results[repo]
        )
        indexed_results[repo][secret_type] = (
            {} if secret_type not in indexed_results[repo] else indexed_results[repo][secret_type]
        )
        indexed_results[repo][secret_type][secret] = result

    return indexed_results


def change_state(hostname, old_result: dict, new_result: dict, verify: bool | str = True) -> None:
    """Change the state of the alert to match the existing result using the GitHub API to update the alert."""
    g = GitHub(hostname=hostname, verify=verify)

    repo_name = new_result["repo"]

    if old_result["repo"] != repo_name:
        LOG.error(f"Repo mismatch: {old_result['repo']} != {repo_name}")
        return

    state_update = {
        "state": old_result["state"],
        "resolution": old_result["resolution"],
        "resolution_comment": old_result["resolution_comment"],
    }

    alert_number = new_result["url"].split("/")[-1]

    LOG.debug(f"Changing state of alert {repo_name}/{alert_number} to {state_update}")

    g.query_once(
        "repo",
        repo_name,
        f"/secret-scanning/alerts/{alert_number}",
        data=state_update,
        method="PATCH",
    )

    return


def resolve_duplicates(
    indexed_results: dict, matching_secrets_lookup: dict, hostname: str, verify: bool | str = True
) -> None:
    """Resolve duplicates by matching on a new secret type and updating the state of the alert to match the existing result."""
    for repo, repo_results in indexed_results.items():
        LOG.debug(repo_results)

        for old_secret_type, new_secret_type in matching_secrets_lookup.items():
            try:
                old_results = repo_results[old_secret_type]
            except KeyError:
                LOG.debug(f"No results found for secret type: {old_secret_type}")
                continue

            for secret, old_result in old_results.items():
                try:
                    new_result = repo_results[new_secret_type][secret]
                    LOG.debug(f"Found matching alert: {new_result}")
                except KeyError:
                    continue

                if new_result["state"] != old_result["state"]:
                    LOG.info(f"State mismatch, updating state: {new_result['state']} != {old_result['state']}")

                    if old_result["state"] != "pattern_edited":
                        change_state(hostname, old_result, new_result, verify=verify)


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
        "--debug", "-d", action="store_true", help="Enable debug logging"
    )
    parser.add_argument(
        "--add-matching-secret",
        "-a",
        action="append",
        nargs=2,
        metavar=("OLD_TYPE", "NEW_TYPE"),
        help="Add a new pair of matched secret types",
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
    verify = True

    if args.ca_cert_bundle:
        verify = args.ca_cert_bundle

    if args.no_verify_tls:
        verify = False
        LOG.warning("Disabling TLS verification. This is insecure and should not be used in production")
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if not GitHub.check_name(args.name, scope):
        raise ValueError("Invalid name: %s for %s", args.name, scope)

    # Update matching secrets with CLI arguments
    matching_secrets = MATCHING_SECRETS.copy()
    if args.add_matching_secret:
        matching_secrets.extend(args.add_matching_secret)

    # now make lookup
    matching_secrets_lookup = {k: v for k, v in matching_secrets}

    # find secret scanning alerts
    results = list_secret_scanning_alerts(name, scope, hostname, state=state, since=since, include_secret=True, verify=verify)
    if not results:
        LOG.info("No secret scanning alerts found")
        return

    # index results by secret and type for easy lookup
    indexed_results = index_results_by_secret(results)

    resolve_duplicates(indexed_results, matching_secrets_lookup, hostname, verify=verify)


if __name__ == "__main__":
    main()
