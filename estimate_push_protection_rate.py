#!/usr/bin/env python3

"""Estimate how many secrets would have been detected in a list of existing secret detections, and a list of which patterns have push protection now."""

import argparse
import json
from datetime import datetime, timezone


def add_args(parser: argparse.ArgumentParser) -> None:
    """Add command line arguments to the parser."""
    parser.add_argument(
        "secrets_file",
        type=str,
        help="Path to the file containing the list of secrets",
    )
    parser.add_argument(
        "patterns_file",
        type=str,
        help="Path to the file containing the list of patterns with push protection",
    )


def main() -> None:
    """Command line entry point."""
    parser = argparse.ArgumentParser(
        description="Estimate push protection rate for secrets"
    )
    add_args(parser)
    args = parser.parse_args()
    
    with open(args.patterns_file, "r") as f:
        patterns: set = {line.strip() for line in f if line.strip()}
    
    with open(args.secrets_file, "r") as f:
        secrets = json.load(f)

    total_secrets = len(secrets)
    protected_secrets = [secret for secret in secrets if secret.get("secret_type") in patterns]

    print(f"Total secrets: {total_secrets}")
    print(f"Protected secrets: {len(protected_secrets)}")

    if total_secrets > 0:
        protection_rate = (len(protected_secrets) / total_secrets) * 100
        print(f"Estimated push protection rate: {protection_rate:.2f}%")
    else:
        print("No secrets found to evaluate.")

    # now evaluate how often we'd expect to block pushes, using the `first_commit_date` field
    # that's in ISO format with a Z suffix
    now = datetime.now(timezone.utc)

    # find the oldest blocked commit
    earliest_blocked_commit_date = min([
        datetime.fromisoformat(secret["first_commit_date"].replace("Z", "+00:00"))
        for secret in protected_secrets
    ])

    blocking_timespan = now - earliest_blocked_commit_date
    rate = len(protected_secrets) / blocking_timespan.days if blocking_timespan.days > 0 else len(protected_secrets)

    print(f"Estimated secrets blocked per day since {earliest_blocked_commit_date.date()}: {rate:.2f}")


if __name__ == "__main__":
    main()
