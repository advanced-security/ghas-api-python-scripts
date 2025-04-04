#!/usr/bin/env python3

"""Close all open code scanning alerts for a repository."""

from githubapi import GitHub
import argparse
import logging
from tqdm import tqdm


LOG = logging.getLogger(__name__)


def update_code_scanning_alert(
    g: GitHub,
    repo_name: str,
    alert_number: int,
    state: str,
    resolution: str,
    resolution_comment: str,
    dry_run: bool = False,
) -> None:
    """Update a code scanning alert using the GitHub API."""
    state_update = {
        "state": state,
        "dismissed_reason": resolution,
        "dismissed_comment": resolution_comment,
        "create_request": False,
    }

    if not dry_run:
        g.query_once(
            "repo",
            repo_name,
            f"/code-scanning/alerts/{alert_number}",
            data=state_update,
            method="PATCH",
        )
    else:
        print(
            f"Would have updated alert {repo_name}#{alert_number} with {state_update}"
        )


def close_code_scanning_alerts(
    github: GitHub, owner: str, repo: str, resolution: str, dry_run: bool = False
) -> None:
    """Close all open code scanning alerts for a repository."""
    repo_name = f"{owner}/{repo}"

    # Get all open code scanning alerts for the repository.
    alerts = github.list_code_scanning_alerts(repo_name, scope="repo", state="open", progress=False)

    counter = 0

    with tqdm(total=None, desc=f"Closing alerts for {repo_name}", unit=" alerts") as pbar:
        # Close each alert.
        for alert in alerts:
            update_code_scanning_alert(
                github,
                repo_name,
                alert["number"],
                state="dismissed",
                resolution=resolution,
                resolution_comment="Closed by scripting",
                dry_run=dry_run,
            )
            counter += 1
            pbar.update(1)

    print(f"Closed {counter} code scanning alerts for {owner}/{repo}")
    return None


def add_args(parser: argparse.ArgumentParser) -> None:
    """Add command line arguments to the parser."""
    parser.add_argument(
        "repo_name",
        type=str,
        help="The owner/repo of the repository to close alerts for.",
    )
    parser.add_argument(
        "--resolution",
        type=str,
        default="used in tests",
        choices=["false positive", "won't fix", "used in tests"],
        help="The resolution of the alert.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the alerts that would be closed, but don't actually close them.",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Print debug messages to the console.",
    )
    return None


def main() -> None:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    add_args(parser)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO if not args.debug else logging.DEBUG)

    github = GitHub()

    try:
        owner, repo = args.repo_name.split("/")
    except ValueError:
        LOG.error(f"Invalid repository name: {args.repo_name}")
        exit(1)

    close_code_scanning_alerts(
        github, owner, repo, args.resolution, dry_run=args.dry_run
    )

    return None


if __name__ == "__main__":
    main()
