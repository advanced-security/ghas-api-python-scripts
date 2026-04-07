#!/usr/bin/env python3

"""Get secret scanning scan history progress for repos across an enterprise, org, or single repo.

Calls GET /repos/{owner}/{repo}/secret-scanning/scan-history for each repo and outputs
a summary of backfill scan status with progress bars, or a detailed markdown table.

Supports cascading:
  - Enterprise → Orgs → Repos
  - Org → Repos
  - Single repo via owner/repo

https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning/secret-scanning?apiVersion=2022-11-28#get-secret-scanning-scan-history-for-a-repository
"""

import argparse
import logging
import math
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime

from githubapi import GitHub

LOG = logging.getLogger(__name__)

BAR_WIDTH = 30
DEFAULT_CONCURRENCY = 10


@dataclass
class ScanRow:
    """A single scan entry for a repo."""

    repo: str
    category: str
    scan_type: str
    status: str
    started_at: str | None = None
    completed_at: str | None = None


@dataclass
class RepoResult:
    """Result of querying scan history for a single repo."""

    repo: str
    is_error: bool = False
    error: str | None = None
    rows: list[ScanRow] = field(default_factory=list)


def resolve_repos(g: GitHub, scope: str, name: str) -> list[str]:
    """Resolve the list of repos to query based on scope."""
    if scope == "repo":
        return [name]

    orgs: list[str] = []
    if scope == "ent":
        print(f"Fetching orgs for enterprise '{name}'...", file=sys.stderr)
        try:
            orgs = g.list_enterprise_orgs(name)
        except Exception as e:
            LOG.error("Failed to list orgs for enterprise '%s': %s", name, e)
            LOG.warning(
                "Ensure your token has the read:enterprise scope "
                "(e.g. gh auth refresh --scopes read:enterprise)"
            )
            return []
        print(f"Found {len(orgs)} org(s)", file=sys.stderr)
    elif scope == "org":
        orgs = [name]

    repos: list[str] = []
    for org in orgs:
        print(f"Fetching repos for org '{org}'...", file=sys.stderr)
        try:
            org_repos = list(g.list_org_repos(org))
        except Exception as e:
            LOG.warning("Failed to list repos for org '%s': %s", org, e)
            continue
        print(f"  Found {len(org_repos)} repo(s) in '{org}'", file=sys.stderr)
        repos.extend(org_repos)

    return repos


def _extract_scan_rows(history: dict, repo_nwo: str) -> list[ScanRow]:
    """Extract scan rows from a scan history response."""
    rows: list[ScanRow] = []

    for category_key, category_label in [
        ("backfill_scans", "backfill"),
        ("incremental_scans", "incremental"),
        ("pattern_update_scans", "pattern_update"),
    ]:
        for scan in history.get(category_key, []):
            rows.append(
                ScanRow(
                    repo=repo_nwo,
                    category=category_label,
                    scan_type=scan.get("type", ""),
                    status=scan.get("status", ""),
                    started_at=scan.get("started_at"),
                    completed_at=scan.get("completed_at"),
                )
            )

    for scan in history.get("custom_pattern_backfill_scans", []):
        slug = scan.get("pattern_slug", "unknown")
        rows.append(
            ScanRow(
                repo=repo_nwo,
                category=f"custom_pattern ({slug})",
                scan_type=scan.get("type", ""),
                status=scan.get("status", ""),
                started_at=scan.get("started_at"),
                completed_at=scan.get("completed_at"),
            )
        )

    return rows


def _fetch_scan_history(g: GitHub, repo_nwo: str) -> RepoResult:
    """Fetch scan history for a single repo. Returns a RepoResult."""
    try:
        history = g.get_secret_scanning_scan_history(repo_nwo)
    except Exception as e:
        error_msg = str(e)
        # Try to extract the API error message
        match = re.search(r'"message":\s*"([^"]+)"', error_msg)
        short = match.group(1) if match else error_msg
        return RepoResult(repo=repo_nwo, is_error=True, error=short)

    rows = _extract_scan_rows(history, repo_nwo)
    if not rows:
        rows.append(
            ScanRow(
                repo=repo_nwo,
                category="-",
                scan_type="-",
                status="no scan data",
            )
        )
    return RepoResult(repo=repo_nwo, rows=rows)


def query_all_repos(
    g: GitHub, repos: list[str], concurrency: int = DEFAULT_CONCURRENCY
) -> tuple[list[ScanRow], list[RepoResult]]:
    """Query scan history for all repos concurrently.

    Returns (all_rows, errors).
    """
    all_rows: list[ScanRow] = []
    errors: list[RepoResult] = []

    print(
        f"\nQuerying scan history for {len(repos)} repo(s) "
        f"({concurrency} concurrent)...\n",
        file=sys.stderr,
    )

    def _worker(repo: str) -> RepoResult:
        # Each thread gets its own GitHub client to avoid sharing
        # the non-thread-safe requests.Session across threads.
        thread_gh = GitHub(
            hostname=g.hostname, verify=g.session.verify
        )
        return _fetch_scan_history(thread_gh, repo)

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {
            executor.submit(_worker, repo): repo for repo in repos
        }
        for future in as_completed(futures):
            result = future.result()
            if result.is_error:
                errors.append(result)
            else:
                all_rows.extend(result.rows)

    return all_rows, errors


def _parse_completed_date(date_str: str | None) -> datetime | None:
    """Parse a completed_at date string, returning None on failure."""
    if not date_str or date_str == "-":
        return None
    normalized = date_str[:-1] + "+00:00" if date_str.endswith("Z") else date_str
    try:
        return datetime.fromisoformat(normalized)
    except (ValueError, TypeError):
        return None


def print_progress_summary(
    all_rows: list[ScanRow],
    errors: list[RepoResult],
    total_repos: int,
) -> None:
    """Print the summary with progress bars."""
    success_repos = total_repos - len(errors)

    print()
    print(
        f"Secret Scanning History Progress ({success_repos}/{total_repos} repos reporting)"
    )
    print("=" * 70)

    # Filter out placeholder rows
    scan_rows = [r for r in all_rows if r.category != "-"]

    # Group by (category, scan_type)
    groups: dict[tuple[str, str], list[ScanRow]] = {}
    for row in scan_rows:
        key = (row.category, row.scan_type)
        groups.setdefault(key, []).append(row)

    # Sort categories in logical order
    category_order = {"backfill": 0, "incremental": 1, "pattern_update": 2}
    sorted_keys = sorted(
        groups.keys(),
        key=lambda k: (category_order.get(k[0], 3), k[1]),
    )

    last_category = ""
    for cat, scan_type in sorted_keys:
        if cat != last_category:
            print(f"\n  {cat.upper()}")
            last_category = cat

        group = groups[(cat, scan_type)]
        total = len(group)
        if total == 0:
            continue
        completed_count = sum(1 for r in group if r.status == "completed")
        in_progress_count = sum(1 for r in group if r.status == "in_progress")
        pct = round((completed_count / total) * 100)
        missing_count = max(success_repos - total, 0)

        # Most recent completed timestamp
        completed_dates = [
            _parse_completed_date(r.completed_at)
            for r in group
            if r.status == "completed"
        ]
        valid_dates = [d for d in completed_dates if d is not None]
        last_completed_str = (
            max(valid_dates).strftime("%Y-%m-%d") if valid_dates else "-"
        )

        filled_len = min(math.floor(BAR_WIDTH * completed_count / total), BAR_WIDTH)
        progress_len = min(
            math.floor(BAR_WIDTH * in_progress_count / total),
            BAR_WIDTH - filled_len,
        )
        empty_len = BAR_WIDTH - filled_len - progress_len

        bar = "=" * filled_len + ">" * progress_len + " " * empty_len

        stats = f"{completed_count}/{total} done"
        if in_progress_count > 0:
            stats += f", {in_progress_count} in progress"
        if missing_count > 0:
            stats += f", {missing_count} n/a"
        stats += f", last: {last_completed_str}"

        label = f"{scan_type:<16}"
        print(f"    {label} [{bar}] {pct:3d}%  ({stats})")

    print()


def print_pending_repos(all_rows: list[ScanRow]) -> None:
    """Print a markdown table of repos that haven't completed all scans."""
    scan_rows = [r for r in all_rows if r.category != "-"]
    pending = [r for r in scan_rows if r.status != "completed"]

    if not pending:
        return

    pending.sort(key=lambda r: (r.repo, r.category, r.scan_type))
    print(f"### Repos not yet completed ({len(pending)})")
    print()
    print("| Repo | Category | Type | Status | Started | Completed |")
    print("| --- | --- | --- | --- | --- | --- |")
    for row in pending:
        started = row.started_at or "-"
        completed = row.completed_at or "-"
        print(
            f"| {row.repo} | {row.category} | {row.scan_type} "
            f"| {row.status} | {started} | {completed} |"
        )
    print()


def print_detailed_table(all_rows: list[ScanRow]) -> None:
    """Print a full markdown table with per-repo scan details."""
    print()
    print("| Repo | Category | Type | Status | Started | Completed |")
    print("| --- | --- | --- | --- | --- | --- |")
    for row in all_rows:
        started = row.started_at or "-"
        completed = row.completed_at or "-"
        print(
            f"| {row.repo} | {row.category} | {row.scan_type} "
            f"| {row.status} | {started} | {completed} |"
        )


def print_errors(errors: list[RepoResult]) -> None:
    """Print repos that had errors."""
    if not errors:
        return

    print(f"Repos with errors ({len(errors)}):", file=sys.stderr)
    for e in errors:
        print(f"  {e.repo}: {e.error}", file=sys.stderr)
    print(file=sys.stderr)


def add_args(parser: argparse.ArgumentParser) -> None:
    """Add command-line arguments to the parser."""
    scope_group = parser.add_mutually_exclusive_group(required=True)
    scope_group.add_argument(
        "--enterprise",
        type=str,
        help="GitHub Enterprise slug. Lists all orgs, then all repos per org.",
    )
    scope_group.add_argument(
        "--org",
        type=str,
        help="GitHub Organization name. Lists all repos in the org.",
    )
    scope_group.add_argument(
        "--repo",
        type=str,
        help="A single repository in owner/repo format.",
    )
    parser.add_argument(
        "--detailed",
        action="store_true",
        help="Show full markdown table with per-repo scan details instead of summary progress bars.",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help=f"Number of concurrent API requests (default: {DEFAULT_CONCURRENCY}).",
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
        help="Path to CA certificate bundle in PEM format (e.g. for self-signed server certificates)",
    )
    parser.add_argument(
        "--no-verify-tls",
        action="store_true",
        help="Do not verify TLS connection certificates (warning: insecure)",
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

    logging.basicConfig(
        level=(
            logging.DEBUG
            if args.debug
            else logging.INFO
            if not args.quiet
            else logging.ERROR
        ),
        format="%(asctime)s %(levelname)s %(message)s",
    )

    # Determine scope and name
    if args.enterprise:
        scope, name = "ent", args.enterprise
    elif args.org:
        scope, name = "org", args.org
    else:
        scope, name = "repo", args.repo

    if not GitHub.check_name(name, scope):
        print(f"Error: Invalid name '{name}' for scope '{scope}'", file=sys.stderr)
        sys.exit(1)

    verify: bool | str = True
    if args.ca_cert_bundle:
        verify = args.ca_cert_bundle
    if args.no_verify_tls:
        verify = False
        LOG.warning(
            "Disabling TLS verification. This is insecure and should not be used in production."
        )
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    g = GitHub(hostname=args.hostname, verify=verify)

    # Resolve repos
    repo_list = resolve_repos(g, scope, name)
    if not repo_list:
        print(
            "Error: No repos resolved. Provide --enterprise, --org, or --repo.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Query scan history
    all_rows, errors = query_all_repos(g, repo_list, concurrency=args.concurrency)

    # Output
    if args.detailed:
        print_detailed_table(all_rows)

    print_progress_summary(all_rows, errors, total_repos=len(repo_list))
    print_pending_repos(all_rows)
    print_errors(errors)


if __name__ == "__main__":
    main()
