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
    parser.add_argument(
        "--cut-off-date",
        type=str,
        default=None,
        help="ISO date string to filter secrets detected after this date (e.g., 2023-01-01)",
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

    secrets_count = len(secrets)
    protected_secrets = [secret for secret in secrets if secret.get("secret_type") in patterns]
    protected_secrets_count = len(protected_secrets)

    print(f"Total secrets: {secrets_count}")
    print(f"Protected secrets: {protected_secrets_count}")

    if secrets_count > 0:
        protection_rate = (protected_secrets_count / secrets_count) * 100
        print(f"Estimated push protection rate: {protection_rate:.2f}%")
    else:
        print("No secrets found to evaluate.")
        return

    # now evaluate how often we'd expect to block pushes, using the `first_commit_date` field
    # that's in ISO format with a Z suffix
    now = datetime.now(timezone.utc)

    cut_off_date = args.cut_off_date
    cut_off_datetime = now

    if cut_off_date is not None:
        try:
            # add a time and TZ if just a date is provided
            if len(cut_off_date) == 10:
                cut_off_date += "T00:00:00+00:00"
            # Handle 'Z' suffix for UTC
            if cut_off_date.endswith("Z"):
                cut_off_date = cut_off_date.replace("Z", "+00:00")
            cut_off_datetime = datetime.fromisoformat(cut_off_date)
            remaining_protected_secrets = [
                secret for secret in protected_secrets
                if "first_commit_date" in secret and datetime.fromisoformat(secret["first_commit_date"].replace("Z", "+00:00")) >= cut_off_datetime
            ]
            remaining_secrets = [
                secret for secret in secrets
                if "first_commit_date" in secret and datetime.fromisoformat(secret["first_commit_date"].replace("Z", "+00:00")) >= cut_off_datetime
            ]
        except ValueError:
            print(f"Invalid cut-off date format: {cut_off_date}. Expected ISO format.")
            return
        
        if not remaining_protected_secrets:
            print("No protected secrets found after applying cut-off date filter.")
            return
        else:
            remaining_secrets_count = len(remaining_secrets)
            remaining_protected_secrets_count = len(remaining_protected_secrets)
            print(f"Total secrets after cut-off date: {remaining_secrets_count}")
            print(f"Protected secrets after cut-off date: {remaining_protected_secrets_count}")
            protection_rate = (remaining_protected_secrets_count / remaining_secrets_count) * 100
            print(f"Estimated push protection rate after cut-off date: {protection_rate:.2f}%")
    else:
        remaining_protected_secrets = protected_secrets

    # get FPs for closed secrets, and estimate for any open ones
    false_positives = 0

    false_positives += sum([1 for secret in remaining_protected_secrets if secret.get("state") == "closed" and secret.get("resolution") == "false_positive"])
    false_positives += sum([1 for secret in remaining_protected_secrets if secret.get("state") == "open"]) // 100

    print(f"Measured + expected false positives: {false_positives}")

    if cut_off_date:
        earliest_date = cut_off_datetime
    else:
    # find the oldest blocked commit with an accessible commit
        earliest_date = min((
            datetime.fromisoformat(secret["first_commit_date"].replace("Z", "+00:00")) if "first_commit_date" in secret else now
            for secret in remaining_protected_secrets
        ))

    blocking_timespan = now - earliest_date
    count_without_false_positives = len(remaining_protected_secrets) - false_positives
    rate = count_without_false_positives / blocking_timespan.days if blocking_timespan.days > 0 else count_without_false_positives

    print(f"Estimated secrets blocked per day since {earliest_date.date()}: {rate:.2f}")
    print(f"                      ... per week ...            : {rate * 7:.2f}")
    print(f"                      ... per month ...           : {rate * 30:.2f}")
    print(f"                      ... per year ...            : {rate * 365:.2f}")

if __name__ == "__main__":
    main()
