#!/usr/bin/env python3

"""List secret scanning alerts for a GitHub repository, organization or Enterprise."""

import sys
import argparse
import logging
import datetime
import json
from typing import Generator, Any
from defusedcsv import csv  # type: ignore
from githubapi import GitHub, parse_date
from requests.exceptions import HTTPError


LOG = logging.getLogger(__name__)


def make_result(
   g: GitHub, alert: dict, scope: str, name: str, include_secret: bool = True, include_locations: bool = False, include_commit: bool = False
) -> dict | None:
    """Make a "flat" alert result from the raw alert data."""
    try:
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
            ),
        }

        first_location = alert.get("first_location_detected")
        if first_location is not None:
            if 'path' in first_location and 'start_line' in first_location and 'start_column' in first_location:
                result["first_location"] = f"{first_location['path']}:{first_location['start_line']}:{first_location['start_column']}@{first_location.get('commit_sha', '')}"

        if include_commit:
            # use decorated alert info, if it's there
            if alert.get("commit") is not None:
                commit_info = alert["commit"]
                result["first_commit_date"] = commit_info["committer"]["date"]
                result["first_commit_author"] = f"{commit_info["author"]["name"]} <{commit_info["author"]["email"]}>"

        if include_locations:
            # use decorated alert info, if it's there
            locations = alert.get("locations")
            if locations:
                result["locations"] = ";".join([f"{loc['details']['path']}:{loc['details']['start_line']}:{loc['details']['start_column']}@{loc['details']['commit_sha']}" for loc in locations if loc.get("type") == "commit"])

        if include_secret:
            result["secret"] = alert["secret"]

        return result
    except KeyboardInterrupt:
        LOG.info("Stopped by user")
        return None
    except Exception as e:
        LOG.error(f"Error processing alert: {e}")
        return {}


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
        (result["first_location"] if "first_location" in result else None),
        result["first_commit_date"] if "first_commit_date" in result else None,
        result["first_commit_author"] if "first_commit_author" in result else None,
        result["locations"] if "locations" in result else None,
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
            "first_location",
            "first_commit_date",
            "first_commit_author",
            "locations",
        ]
    )

    for result in results:
        try:
            writer.writerow(to_list(result))
        except KeyboardInterrupt:
            LOG.info("Stopped by user")
            return

def decorate_alerts(g: GitHub, alerts: Generator[dict[str, Any], None, None], include_locations: bool = False, include_commit: bool = False) -> Generator[dict[str, Any], None, None]:
    """Decorate alerts with additional information, for both the raw and make_result outputs.
    
    Resolve locations and commit information, if that was asked for.
    """
    try:
        location_data = None

        for alert in alerts:
            first_location: Any | None = alert.get("first_location_detected", None)

            if include_locations:
                if "has_more_locations" in alert and not alert["has_more_locations"]:
                    pass
                else:
                    result = None
                    try:
                        result = g._get(alert["locations_url"])
                        location_data = result.json()
                        if first_location is None and location_data and 'type' in location_data[0] and location_data[0]['type'] == 'commit' and 'details' in location_data[0]:
                            first_location = location_data[0]['details']
                        alert["locations"] = location_data
                    except json.JSONDecodeError as e:
                        LOG.error(f"Error decoding JSON from locations URL for alert location data: {e}")
                        if result is not None:
                            LOG.debug(result.text)
                    except HTTPError as e:
                        if e.response.status_code == 404:
                            LOG.error("Locations URL not found for alert")

            if first_location is not None and "first_location_detected" not in alert:
                alert["first_location_detected"] = first_location

            if include_commit:
                if first_location is None:
                    # we *have* to get the location info, despite not having --include-locations set
                    result = None
                    try:
                        result = g._get(alert["locations_url"])
                        location_data = result.json()
                        if location_data and 'type' in location_data[0] and location_data[0]['type'] == 'commit' and 'details' in location_data[0]:
                            first_location = location_data[0]['details']
                    except json.JSONDecodeError as e:
                        LOG.error(f"Error decoding JSON from locations URL for alert location data: {e}")
                        if result is not None:
                            LOG.debug(result.text)
                    except HTTPError as e:
                        if e.response.status_code == 404:
                            LOG.error("Locations URL not found for alert")
                if first_location is not None:
                    commit_url = first_location.get("commit_url")
                    if commit_url:
                        try:
                            result = g._get(commit_url)
                            commit_info = result.json()
                            alert["commit"] = commit_info
                        except json.JSONDecodeError as e:
                            LOG.error(f"Error decoding JSON from commit URL: {e}")
                            if result is not None:
                                LOG.debug(result.text)
                        except HTTPError as e:
                            if e.response.status_code == 404:
                                LOG.warning(f"No commit data found for alert, commit URL not found: {commit_url}")

            yield alert
    except KeyboardInterrupt:
        LOG.error("Stopped by user")
        return


def list_secret_scanning_alerts(
    name,
    scope: str,
    hostname: str,
    state: str | None = None,
    since: datetime.datetime | None = None,
    include_secret: bool = False,
    include_locations: bool = False,
    include_commit: bool = False,
    bypassed: bool = False,
    raw: bool = False,
    generic: bool = False,
    verify: bool | str = True,
    progress: bool = True,
) -> Generator[dict[str, Any], None, None] | None:
    """List secret scanning alerts for a repo/org/Enterprise using the GitHub API.
    
    Decorate the alerts with additional information, if requested.

    Output either the raw alert data, or flattened results.
    """
    g = GitHub(hostname=hostname, verify=verify)
    alerts = g.list_secret_scanning_alerts(
        name, state=state, since=since, scope=scope, bypassed=bypassed, generic=generic, progress=progress
    )

    alerts = decorate_alerts(g, alerts, include_locations=include_locations, include_commit=include_commit)

    if raw:
        return alerts
    else:
        for alert in alerts:
            result = make_result(g, alert, scope, name, include_secret=include_secret, include_locations=include_locations, include_commit=include_commit)
            if result is not None:
                yield result
            else:
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
        "--generic",
        "-g",
        action="store_true",
        help="Include generic secret types (not just vendor secret types/custom patterns, which is the default)",
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
        "--include-locations",
        "-l",
        action="store_true",
        help="Include locations in the output",
    )
    parser.add_argument(
        "--include-commit",
        "-c",
        action="store_true",
        help="Include commit date and committer in the output",
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
        "--quote-all", "-Q", action="store_true", help="Quote all fields in CSV output"
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
        "-q",
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
    include_secret = not args.no_include_secret
    include_locations = args.include_locations
    include_commit = args.include_commit
    bypassed = args.bypassed
    generic = args.generic
    verify = True

    if args.ca_cert_bundle:
        verify = ca_cert_bundle

    if args.no_verify_tls:
        verify = False
        LOG.warning("Disabling TLS. This is insecure and should not be used in production")
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if not GitHub.check_name(name, scope):
        raise ValueError("Invalid name: %s for %s", name, scope)

    results = list_secret_scanning_alerts(
        name,
        scope,
        hostname,
        state=state,
        since=since,
        progress=not args.quiet,
        include_secret=include_secret,
        include_locations=include_locations,
        include_commit=include_commit,
        bypassed=bypassed,
        raw=args.raw,
        generic=generic,
        verify=verify
    )

    LOG.debug(results)

    if args.json:
        print(json.dumps(list(results), indent=2))
    else:
        output_csv(results, args.quote_all)  # type: ignore


if __name__ == "__main__":
    main()
