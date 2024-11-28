#!/usr/bin/env python3

"""Add CodeQL metadata to Code Scanning alerts.

This can be the abbreviated version of the JSON output supported by the partner script `list_code_scanning_alerts.py`,
or can be the full output from the GitHub API.

The metadata can either be in the format provided by the `codeql resolve metadata` command,
or in the format produced by the script `parse_ql` by the same author as this script.
"""

import json
import argparse
import logging
from html import escape


LOG = logging.getLogger(__name__)

LANGUAGE_LOOKUP = {
    "js": "javascript",
    "py": "python",
    "rb": "ruby"
}


def fix_all_metadata(metadata: dict, metadata_format: str) -> None:
    """Fix up all metadata entries in the dictionary."""
    for rule_id, rule_metadata in metadata.items():
        if metadata_format == "codeql":
            fixup_rule_metadata_codeql(rule_metadata)
        elif metadata_format == "parse_ql":
            fixup_rule_metadata_parse_ql(rule_metadata)
        if "id" in rule_metadata:
            del rule_metadata["id"]
        if "tags" in rule_metadata:
            LOG.debug("Tags: %s", rule_metadata["tags"])
            # pull out main CWE from the tags
            cwe_tags = [tag for tag in rule_metadata["tags"] if tag.startswith("external/cwe/cwe-")]
            if cwe_tags:
                rule_metadata["cwe"] = cwe_tags[0].replace("external/cwe/cwe-", "")


def fixup_rule_metadata_codeql(rule_metadata: dict) -> None:
    """Fix up the rule metadata to make it more usable."""

    # tags are output as a single string, but we want them as a list
    if "tags" in rule_metadata:
        rule_metadata["tags"] = rule_metadata["tags"].split(" ")

    if "security-severity" in rule_metadata:
        try:
            rule_metadata["security-severity"] = float(rule_metadata["security-severity"])
        except:
            LOG.warning(
                "Could not parse security-severity in rule %s as float: %s",
                rule_metadata.get("id", "unknown ID"),
                rule_metadata["security-severity"]
            )
    
    # add language by parsing the rule ID
    language_from_id = rule_metadata["id"].split("/")[0]
    rule_metadata["language"] = LANGUAGE_LOOKUP.get(language_from_id, language_from_id)


def fixup_rule_metadata_parse_ql(rule_metadata: dict) -> None:
    """Fix up the rule metadata to make it more usable."""

    # this is just used to correlate the QHelp files with the .ql files, we don't need to retain it
    if "filename" in rule_metadata:
        del rule_metadata["filename"]


def enrich_alerts(alerts: list, metadata: dict) -> None:
    """Enrich the alerts with the rule metadata."""
    for alert in alerts:
        if alert["tool_name"] == "CodeQL":
            LOG.debug("Adding metadata")
            rule_id = alert["rule_id"]
            LOG.debug("Rule ID: %s", rule_id)
            rule_metadata = metadata.get(rule_id, {})

            if not rule_metadata:
                LOG.warning("No metadata found for rule ID %s", rule_id)
                LOG.debug("All metadata keys: %s", metadata.keys())
            LOG.debug("Metadata: %s", rule_metadata)
            alert.update(rule_metadata)


def format_headings(keys: list) -> str:
    """Format the headings of the table."""
    cells = []
    for key in keys:
        cells.append("<th>{}</th>".format(escape(key)))
    return "<tr>{}</tr>".format("".join(cells))


def format_row(alert: dict, keys: list) -> str:
    """Format a single row of the table."""
    cells = []
    for key in keys:
        value = alert.get(key)
        if value is None:
            value = "-"
        cells.append("<td>{}</td>".format(escape(str(value))))
    return "<tr>{}</tr>".format("".join(cells))


def html_output(alerts: list) -> str:
    """Generate a simple HTML representation of the alerts, in a table. Use HTML escaping."""
    fields = ["rule_id", "cwe", "description", "problem.severity", "security-severity"]

    heading = format_headings(fields)

    rows = []
    for alert in alerts:
        rows.append(format_row(alert, fields))

    return "<table>\n{}\n{}</table>".format(heading, "\n".join(rows))


def add_args(parser: argparse.ArgumentParser) -> None:
    """Add command-line arguments to the parser."""
    parser.add_argument(
        "alerts",
        type=argparse.FileType("r"),
        help="JSON file containing the alerts to enrich",
    )
    parser.add_argument(
        "metadata",
        type=argparse.FileType("r"),
        help="JSON file containing the metadata to add to the alerts, which must be indexed by the rule ID",
    )
    parser.add_argument(
        "--metadata-format",
        "-m",
        choices=["codeql", "parse_ql"],
        default="codeql",
        help="Format of the metadata",
    )
    parser.add_argument(
        "--debug",
        "-d",
        action="store_true",
        help="Print debug information",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["json", "html"],
    )


def main() -> None:
    """Command-line entrypoint."""
    parser = argparse.ArgumentParser(description=__doc__)
    add_args(parser)
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)

    alerts = json.load(args.alerts)
    metadata = json.load(args.metadata)

    fix_all_metadata(metadata, args.metadata_format)
    enrich_alerts(alerts, metadata)

    if args.format == "json":
        print(json.dumps(alerts, indent=2))
    elif args.format == "html":
        print(html_output(alerts))


if __name__ == "__main__":
    main()
